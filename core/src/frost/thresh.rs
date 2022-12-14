use std::collections::*;
use std::fmt;

use elliptic_curve::sec1::Coordinates;
use elliptic_curve::sec1::ToEncodedPoint;
use elliptic_curve::subtle::ConditionallySelectable;
use elliptic_curve::Curve;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sha2::Sha256;
use thiserror::Error;

use super::bip340;
use super::challenge::*;
use super::dkg;
use super::hash::*;
use super::math::*;
use super::serde::*;
use super::sig::TaprootSignature;
use super::sig::{SchnorrPubkey, Signature};

#[derive(Debug, Error)]
pub enum Error {
    #[error("zero cosigners")]
    ZeroCosigners,

    #[error("participant id cannot be zero")]
    ZeroParticipantId,

    #[error("threshold {1} greater than supplied {0} signers")]
    InsufficientCosigners(u32, u32),

    #[error("coefficients list mismatch length with cosigners list ({0} != {1})")]
    CoeffsCosignersMismatchCount(usize, usize),

    #[error("coefficients list mismatch with cosigners list)")]
    CoeffsCosignersMismatch,

    #[error("participant only in round {0}")]
    InvalidSetupRound(u32),

    #[error("unimplemented")]
    Unimplemented,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignerState<M: Math, C: ChallengeDeriver<M>> {
    // Setup variables
    id: u32,
    thresh: u32,

    #[serde_as(as = "Marshal<ScalarSerde<M>>")]
    sk_share: <M::G as Group>::Scalar,

    #[serde_as(as = "Marshal<PointSerde<M>>")]
    vk_share: M::G,

    #[serde_as(as = "Marshal<PointSerde<M>>")]
    vk: M::G,

    lcoeffs: HashMap<u32, WrappedScalar<M>>,

    cosigners: Vec<u32>,
    state: Inner<M>,
    challenge_deriver: C,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Inner<M: Math> {
    Init,
    R1(R1InnerState<M>),
    R2(R2InnerState<M>),
    Final,
}

impl<M: Math> Inner<M> {
    fn legacy_round(&self) -> u32 {
        match self {
            Self::Init => 1,
            Self::R1(_) => 2,
            Self::R2(_) => 3,
            Self::Final => 4,
        }
    }
}

impl<M: Math> Default for Inner<M> {
    fn default() -> Self {
        Self::Init
    }
}

impl<M: Math, C: ChallengeDeriver<M>> SignerState<M, C> {
    /// Takes a final participant state and initializes a new signer with it.
    /// Some information may be redundant.
    pub fn new(
        info: &dkg::R2ParticipantState<M>,
        cosigners: Vec<u32>,
        cderiv: C,
    ) -> Result<SignerState<M, C>, Error> {
        if cosigners.is_empty() {
            return Err(Error::ZeroCosigners);
        }

        let id = info.id();
        let thresh = info.group_thresh();

        if id == 0 {
            return Err(Error::ZeroParticipantId);
        }

        if thresh as usize > cosigners.len() {
            return Err(Error::InsufficientCosigners(thresh, cosigners.len() as u32));
        }

        // Generate the lagrange coefficients.
        // TODO Should we make it so these can be supplied externally?
        let lcoeffs = gen_lagrange_coefficients::<<M::G as Group>::Scalar>(
            cosigners.len() as u32,
            thresh,
            &cosigners,
        );

        // This check should never fail now, should we remove it?
        if lcoeffs.len() != cosigners.len() {
            return Err(Error::CoeffsCosignersMismatchCount(
                lcoeffs.len(),
                cosigners.len(),
            ));
        }

        if !cosigners.iter().all(|id| lcoeffs.contains_key(id)) {
            return Err(Error::CoeffsCosignersMismatch);
        }

        // Wrap them in the serde-able type.
        let lcoeffs = lcoeffs
            .into_iter()
            .map(|(k, v)| (k, WrappedScalar(v)))
            .collect::<_>();

        Ok(SignerState {
            id,
            thresh,
            sk_share: info.sk_share(),
            vk_share: info.vk_share(),
            vk: info.vk(),
            lcoeffs,
            cosigners,
            state: Inner::Init,
            challenge_deriver: cderiv,
        })
    }
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct R1InnerState<M: Math> {
    #[serde_as(as = "Marshal<PointSerde<M>>")]
    cap_d: M::G,

    #[serde_as(as = "Marshal<PointSerde<M>>")]
    cap_e: M::G,

    #[serde_as(as = "Marshal<ScalarSerde<M>>")]
    small_d: <M::G as Group>::Scalar,

    #[serde_as(as = "Marshal<ScalarSerde<M>>")]
    small_e: <M::G as Group>::Scalar,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round1Bcast<M: Math> {
    #[serde_as(as = "Marshal<PointSerde<M>>")]
    pub di: M::G,

    #[serde_as(as = "Marshal<PointSerde<M>>")]
    pub ei: M::G,
}

#[derive(Debug, Error)]
pub enum Round1Error {
    #[error("participant only in round {0}")]
    WrongRound(u32),

    #[error("unimplemented")]
    Unimplemented,
}

/// This is actually the preprocessing step described in some versions, notice
/// there's no message hash we're deciding to sign being passed in.
pub fn round_1(
    signer: &SignerState<Secp256k1Math, Bip340Chderiv>,
    mut rng: &mut impl Rng,
) -> Result<
    (
        SignerState<Secp256k1Math, Bip340Chderiv>,
        Round1Bcast<Secp256k1Math>,
    ),
    Round1Error,
> {
    if signer.state.legacy_round() != 1 {
        return Err(Round1Error::WrongRound(signer.state.legacy_round()));
    }

    // Step 1 - Sample di, ei
    let di = k256::Scalar::random(&mut rng);
    let ei = k256::Scalar::random(&mut rng);

    // Step 2 - Compute Di, Ei
    let big_di = k256::ProjectivePoint::GENERATOR * di;
    let big_ei = k256::ProjectivePoint::GENERATOR * ei;

    // Store di, ei, Di, Ei locally and broadcast Di, Ei
    let mut nsigner = signer.clone();
    nsigner.state = Inner::R1(R1InnerState {
        cap_d: big_di,
        cap_e: big_ei,
        small_d: di,
        small_e: ei,
    });

    let r1bc = Round1Bcast {
        di: big_di,
        ei: big_ei,
    };

    Ok((nsigner, r1bc))
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct R2InnerState<M: Math> {
    // Copied from round 1.
    // No small_d or small_e since they're one-time use.
    #[serde_as(as = "Marshal<PointSerde<M>>")]
    cap_d: M::G,

    #[serde_as(as = "Marshal<PointSerde<M>>")]
    cap_e: M::G,

    // Round 2.
    commitments: HashMap<u32, Round1Bcast<M>>,

    #[serde(with = "hex")]
    msg_digest: [u8; 32],

    #[serde_as(as = "Marshal<ScalarSerde<M>>")]
    c: <M::G as Group>::Scalar,

    cap_rs: HashMap<u32, WrappedPoint<M>>,

    #[serde_as(as = "Marshal<PointSerde<M>>")]
    sum_r: M::G,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round2Bcast<M: Math> {
    #[serde_as(as = "Marshal<ScalarSerde<M>>")]
    pub zi: <M::G as Group>::Scalar,

    #[serde_as(as = "Marshal<PointSerde<M>>")]
    pub vki: M::G,
}

#[derive(Debug, Error)]
pub enum Round2Error {
    #[error("participant only in round {0}")]
    WrongRound(u32),

    #[error("message empty")]
    MsgEmpty,

    #[error("input bcast size {0} mismatch with thresh {1}")]
    InputMismatchThresh(u32, u32),

    #[error("unimplemented")]
    Unimplemented,
}

pub fn round_2(
    signer: &SignerState<Secp256k1Math, Bip340Chderiv>,
    msg_hash: &[u8; 32],
    round2_input: &HashMap<u32, Round1Bcast<Secp256k1Math>>,
) -> Result<
    (
        SignerState<Secp256k1Math, Bip340Chderiv>,
        Round2Bcast<Secp256k1Math>,
    ),
    Round2Error,
> {
    let r1is = match &signer.state {
        Inner::R1(r1is) => r1is,
        _ => return Err(Round2Error::WrongRound(signer.state.legacy_round())),
    };

    // Some checks here we can skip.
    // * Make sure those private d is not empty and not zero
    // * Make sure those private e is not empty and not zero

    let r2iu32 = round2_input.len() as u32;
    if r2iu32 != signer.thresh {
        return Err(Round2Error::InputMismatchThresh(
            round2_input.len() as u32,
            signer.thresh,
        ));
    }

    let mut nsigner = signer.clone();

    // Skipped: Step 2 - Check Dj, Ej on the curve and Store round2Input

    // Store Dj, Ej for further usage.
    // deferred: signer.state.commitments = Some(round2_input);

    // Step 3-6 (all of these r values are rhos in the paper)
    let mut sum_r = k256::ProjectivePoint::IDENTITY;
    let mut ri = k256::Scalar::ZERO; // gets overwritten
    let mut rs = HashMap::<u32, WrappedPoint<Secp256k1Math>>::new();
    for (id, data) in round2_input {
        // Construct the binding balue commitment: (j, m, {Dj, Ej})
        let blob = concat_hash_array(*id, &msg_hash, &round2_input, &signer.cosigners);

        // Step 4 - rj = H(j,m,{Dj,Ej}_{j in [1...t]})
        // TODO We could make this operation faster by being sloppy with it, it
        // wouldn't reduce security afaik.
        let rj = hash_to_field::<k256::Scalar>(&blob);
        if signer.id == *id {
            // DOES THIS EVER GET INVOKED???
            ri = rj;
        }

        // Step 5 - R_j = D_j + r_j*E_j (now this is the big R)
        let rj_ej = data.ei * rj;
        let rj = rj_ej + data.di;
        rs.insert(*id, WrappedPoint(rj));

        // Step 6 - R = R+Rj
        sum_r += rj;
    }

    let r_fmt = bip340::fmt_point(&sum_r.to_affine());
    eprintln!("sum_r: {}", r_fmt);

    // Normalize the point.  This math is a little screwy so make sure it's correct.
    // TODO TODO TODO
    if bip340::has_even_y(sum_r.to_affine()) {
        // Figuring out if it's negative or not is hard.  But once we know, flipping it is easy.
        sum_r = -sum_r;
    }

    // Step 7 - c = H(m, R)
    let c = signer
        .challenge_deriver
        .derive_challenge(&msg_hash, signer.vk, sum_r);

    // Step 9 - zi = di + (ei * ri) + (Li * ski * c)
    let li = signer.lcoeffs[&signer.id].0;
    let liski = li * signer.sk_share;
    let liskic = liski * c;

    let eiri = r1is.small_e * ri;

    // Compute zi = di + (ei * ri) + (Li * ski * c)
    let zi = liskic + eiri + r1is.small_d;

    // Step 8 - Record c, R, Rjs
    nsigner.state = Inner::R2(R2InnerState {
        cap_d: r1is.cap_d,
        cap_e: r1is.cap_d,
        commitments: round2_input.clone(),
        msg_digest: *msg_hash,
        c,
        cap_rs: rs,
        sum_r,
    });

    let r2bc = Round2Bcast {
        zi,
        vki: signer.vk_share,
    };

    Ok((nsigner, r2bc))
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round3Bcast<M: Math> {
    #[serde_as(as = "Marshal<PointSerde<M>>")]
    pub rho: M::G,

    #[serde_as(as = "Marshal<PointSerde<M>>")]
    pub r: M::G,

    #[serde_as(as = "Marshal<ScalarSerde<M>>")]
    pub z: <M::G as Group>::Scalar,

    #[serde_as(as = "Marshal<ScalarSerde<M>>")]
    pub c: <M::G as Group>::Scalar,

    #[serde(with = "hex")]
    pub msg: Vec<u8>,
}

impl<M: Math> Round3Bcast<M> {
    pub fn to_sig(&self) -> Signature<M> {
        Signature {
            z: self.z,
            c: self.c,
        }
    }

    pub fn to_taproot_sig(&self) -> TaprootSignature<M> {
        TaprootSignature {
            r: self.r,
            s: self.z,
        }
    }
}

#[derive(Debug, Error)]
pub enum Round3Error {
    #[error("participant only in round {0}")]
    WrongRound(u32),

    #[error("input bcast size {0} mismatch with thresh {1}")]
    InputMismatchThresh(u32, u32),

    #[error("zjG != right for participant {0}")]
    ParticipantEquivocate(u32),

    #[error("invalid signature (c != c')")]
    InvalidSignature,

    #[error("unimplemented")]
    Unimplemented,
}

pub fn round_3(
    signer: &SignerState<Secp256k1Math, Bip340Chderiv>,
    round3_input: &HashMap<u32, Round2Bcast<Secp256k1Math>>,
) -> Result<
    (
        SignerState<Secp256k1Math, Bip340Chderiv>,
        Round3Bcast<Secp256k1Math>,
    ),
    Round3Error,
> {
    let r2is = match &signer.state {
        Inner::R2(r2is) => r2is,
        _ => return Err(Round3Error::WrongRound(signer.state.legacy_round())),
    };
    let mut nsigner = signer.clone();

    // A bunch of checks we can skip here.

    let r3iu32 = round3_input.len() as u32;
    if r3iu32 != signer.thresh {
        return Err(Round3Error::InputMismatchThresh(r3iu32, signer.thresh));
    }

    let signer_c = r2is.c;
    let signer_rs = r2is.cap_rs.clone();
    let signer_msg = r2is.msg_digest;

    // Step 1-3
    // Step 1: For j in [1...t]
    let mut z = k256::Scalar::zero();
    let flip_parity = !bip340::has_even_y(r2is.sum_r.to_affine());
    for (id, data) in round3_input {
        let zj = data.zi;
        let vkj = data.vki; // FIXME do we just trust this as provided or should we remember their share?

        // Step 2: Verify zj*G = Rj + c*Lj*vkj
        // zj*G
        let zjg = k256::ProjectivePoint::GENERATOR * zj;

        // c*Lj
        let clj = signer_c * signer.lcoeffs[id].0;

        // cLjvkj
        let cljvkj = vkj * clj;

        // Rj + c*Lj*vkj
        let mut rj = signer_rs[id].0;

        // see above
        if flip_parity {
            rj = k256::ProjectivePoint::from(bip340::flip(rj.to_affine()));
        }

        let right = cljvkj + rj;

        // Check equation!
        if zjg != right {
            let zjg_fmt = bip340::fmt_point(&zjg.to_affine());
            let right_fmt = bip340::fmt_point(&right.to_affine());
            eprintln!("zgj != right for {}: {} != {}", id, zjg_fmt, right_fmt);
            return Err(Round3Error::ParticipantEquivocate(*id));
        }

        z += zj;
    }

    // Step 4 - 7: Self verify the signature (z, c)
    let zg = k256::ProjectivePoint::GENERATOR * z; // r
    let cvk = signer.vk * signer_c; // additive not multiplicative!
    let tmp_r = zg - cvk;

    // Step 6 - c' = H(m, R')
    let tmp_c = signer
        .challenge_deriver
        .derive_challenge(&signer_msg, signer.vk, tmp_r);

    // Step 7 - Check c = c'
    if tmp_c != signer_c {
        eprintln!(
            "tmp {}\nsig {}",
            hex::encode(tmp_c.to_repr()),
            hex::encode(signer_c.to_repr())
        );
        return Err(Round3Error::InvalidSignature);
    }

    // Update round number
    nsigner.state = Inner::Final;

    let r3bc = Round3Bcast {
        rho: r2is.sum_r,
        r: zg,
        z,
        c: signer_c,
        msg: signer_msg.to_vec(),
    };

    let rbuf = zg.to_bytes().to_vec();
    eprintln!("thresh r buf {}", hex::encode(rbuf));

    Ok((nsigner, r3bc))
}

/// Builds a commitment, used for the H_1 in the paper.
fn concat_hash_array<M: Math>(
    id: u32,
    msg_hash: &[u8; 32],
    r2i: &HashMap<u32, Round1Bcast<M>>,
    cosigners: &[u32],
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend(u32::to_be_bytes(id));
    buf.extend(msg_hash);

    for cosig_id in cosigners {
        buf.extend(u32::to_be_bytes(*cosig_id));
        let r1b = &r2i[cosig_id];

        let bigdi_bytes = r1b.di.to_bytes(); // `.to_affine()`?
        let bigei_bytes = r1b.ei.to_bytes(); // `.to_affine()`?
        buf.extend(bigdi_bytes.as_ref());
        buf.extend(bigei_bytes.as_ref());
    }

    buf
}

/// Basically just gets a version of a number in the scalar field since we can't
/// rely on it to have native conversions from normal Rust ints.  This isn't
/// fast but we don't do it often so it's probably ok.  Maybe we should make a
/// version that precomputes the table.
fn mult_u32<F: Field>(n: u32) -> F {
    let mut cur = F::one();
    let mut sum = F::zero();

    for i in 0..31 {
        let b = (n >> i) & 0x01;

        if b == 1 {
            sum += cur;
        }

        cur = cur.double();
    }

    sum
}

/// Computes the Lagrange coefficients for a given SSS polynomial, *thing*.  I
/// don't totally understand what it's doing but vsss_rs didn't seem to have an
/// exact coordinate in its polynomial code.
pub fn gen_lagrange_coefficients<F: Field>(
    limit: u32,
    thresh: u32,
    idents: &[u32],
) -> HashMap<u32, F> {
    let mut coeffs = HashMap::new();

    for (i, xi) in idents.iter().enumerate() {
        let xi_f = mult_u32::<F>(*xi);

        let mut num = F::one();
        let mut den = F::one();

        for (j, xj) in idents.iter().enumerate() {
            if i == j {
                continue;
            }

            let xj_f = mult_u32::<F>(*xj);

            num *= xj_f;
            den *= xj_f - xi_f;
        }

        if den.is_zero().into() {
            panic!(
                "divide by zero! limit={}, thresh={}, idents={:?}",
                limit, thresh, idents,
            );
        }

        let res = num * den.invert().unwrap();
        coeffs.insert(*xi as u32, res);
    }

    coeffs
}
