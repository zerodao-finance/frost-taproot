use std::collections::*;
use std::fmt;

use rand::Rng;
use thiserror::Error;

use super::dkg;
use super::math::*;

#[derive(Debug, Error)]
pub enum Error {
    #[error("zero cosigners")]
    ZeroCosigners,

    #[error("threshold out of bounds")]
    ThreshOob,

    #[error("coefficients list mismatch length with cosigners list ({0} != {1})")]
    CoeffsCosignersMismatchCount(usize, usize),

    #[error("coefficients list mismatch with cosigners list)")]
    CoeffsCosignersMismatch,

    #[error("participant only in round {0}")]
    InvalidSetupRound(u32),

    #[error("unimplemented")]
    Unimplemented,
}

/// In the Go code this is just a hash-to-field of the serialized inputs, so we
/// could make this totally general and implement it for all `Math`s, it seems.
pub trait ChallengeDeriver<M: Math>: Clone {
    fn derive_challenge(&self, msg: &[u8], pk: M::G, r: M::G) -> <M::G as Group>::Scalar;
}

#[derive(Clone)]
pub struct UniversalChderiv;

impl<M: Math> ChallengeDeriver<M> for UniversalChderiv {
    fn derive_challenge(&self, msg: &[u8], pk: M::G, r: M::G) -> <M::G as Group>::Scalar {
        let mut buf = msg.to_vec();
        buf.extend(M::group_repr_to_bytes(pk.to_bytes()));
        buf.extend(M::group_repr_to_bytes(r.to_bytes()));
        hash_to_field(&buf)
    }
}

#[derive(Clone)]
pub struct SignerState<M: Math, C: ChallengeDeriver<M>> {
    // Setup variables
    id: u32,
    thresh: u32,
    sk_share: <M::G as Group>::Scalar,
    vk_share: M::G,
    vk: M::G,
    lcoeffs: HashMap<u32, <M::G as Group>::Scalar>,
    cosigners: Vec<u32>,
    state: Inner<M>,
    challenge_deriver: C,
}

#[derive(Clone)]
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

#[derive(Clone)]
pub struct R1InnerState<M: Math> {
    cap_d: M::G,
    cap_e: M::G,
    small_d: <M::G as Group>::Scalar,
    small_e: <M::G as Group>::Scalar,
}

#[derive(Clone)]
pub struct R2InnerState<M: Math> {
    // Copied from round 1.
    // No small_d or small_e since they're one-time use.
    cap_d: M::G,
    cap_e: M::G,

    // Round 2.
    commitments: HashMap<u32, Round1Bcast<M>>,
    msg: Vec<u8>,
    c: <M::G as Group>::Scalar,
    cap_rs: HashMap<u32, M::G>,
    sum_r: M::G,
}

impl<M: Math> Default for Inner<M> {
    fn default() -> Self {
        Self::Init
    }
}

impl<M: Math, C: ChallengeDeriver<M>> SignerState<M, C> {
    pub fn new(
        info: &dkg::R2ParticipantState<M>,
        id: u32,
        thresh: u32,
        lcoeffs: HashMap<u32, <M::G as Group>::Scalar>,
        cosigners: Vec<u32>,
        cderiv: C,
    ) -> Result<SignerState<M, C>, Error> {
        if cosigners.is_empty() || lcoeffs.is_empty() {
            return Err(Error::ZeroCosigners);
        }

        if thresh as usize > cosigners.len() {
            return Err(Error::ThreshOob);
        }

        if lcoeffs.len() != cosigners.len() {
            return Err(Error::CoeffsCosignersMismatchCount(
                lcoeffs.len(),
                cosigners.len(),
            ));
        }

        if !cosigners.iter().all(|id| lcoeffs.contains_key(id)) {
            return Err(Error::CoeffsCosignersMismatch);
        }

        Ok(SignerState {
            id,
            thresh,
            sk_share: info.sk_share,
            vk_share: info.vk_share,
            vk: info.vk,
            lcoeffs,
            cosigners,
            state: Inner::Init,
            challenge_deriver: cderiv,
        })
    }
}

#[derive(Clone)]
pub struct Round1Bcast<M: Math> {
    pub di: M::G,
    pub ei: M::G,
}

#[derive(Clone)]
pub struct Round2Bcast<M: Math> {
    pub zi: <M::G as Group>::Scalar,
    pub vki: M::G,
}

pub struct Round3Bcast<M: Math> {
    pub r: M::G,
    pub z: <M::G as Group>::Scalar,
    pub c: <M::G as Group>::Scalar,
    pub msg: Vec<u8>,
}

impl<M: Math> Round3Bcast<M> {
    pub fn to_sig(&self) -> Signature<M> {
        Signature {
            z: self.z,
            c: self.c,
        }
    }
}

#[derive(Clone)]
pub struct Signature<M: Math> {
    z: <M::G as Group>::Scalar,
    c: <M::G as Group>::Scalar,
}

impl<M: Math> fmt::Debug for Signature<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let z_hex = hex::encode(M::scalar_repr_to_bytes(self.z.to_repr()));
        let c_hex = hex::encode(M::scalar_repr_to_bytes(self.c.to_repr()));
        f.write_fmt(format_args!("{}.{}", z_hex, c_hex))
    }
}

impl<M: Math> PartialEq for Signature<M> {
    fn eq(&self, other: &Self) -> bool {
        (self.z == other.z) && (self.c == other.c)
    }
}

#[derive(Debug, Error)]
pub enum Round1Error {
    #[error("participant only in round {0}")]
    WrongRound(u32),

    #[error("unimplemented")]
    Unimplemented,
}

pub fn round_1<M: Math, C: ChallengeDeriver<M>>(
    signer: &SignerState<M, C>,
    mut rng: &mut impl Rng,
) -> Result<(SignerState<M, C>, Round1Bcast<M>), Round1Error> {
    if signer.state.legacy_round() != 1 {
        return Err(Round1Error::WrongRound(signer.state.legacy_round()));
    }

    // Step 1 - Sample di, ei
    let di = <<M::G as Group>::Scalar as Field>::random(&mut rng);
    let ei = <<M::G as Group>::Scalar as Field>::random(&mut rng);

    // Step 2 - Compute Di, Ei
    let big_di = <M::G as Group>::generator() * di;
    let big_ei = <M::G as Group>::generator() * ei;

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

pub fn round_2<M: Math, C: ChallengeDeriver<M>>(
    signer: &SignerState<M, C>,
    msg: &[u8],
    round2_input: &HashMap<u32, Round1Bcast<M>>,
) -> Result<(SignerState<M, C>, Round2Bcast<M>), Round2Error> {
    let r1is = match &signer.state {
        Inner::R1(r1is) => r1is,
        _ => return Err(Round2Error::WrongRound(signer.state.legacy_round())),
    };

    // Some checks here we can skip.
    // * Make sure those private d is not empty and not zero
    // * Make sure those private e is not empty and not zero

    if msg.is_empty() {
        return Err(Round2Error::MsgEmpty);
    }

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

    // Step 3-6
    let mut sum_r = <M::G as Group>::identity();
    let mut ri = <<M::G as Group>::Scalar as Field>::zero();
    let mut rs = HashMap::<u32, M::G>::new();
    for (id, data) in round2_input {
        // Construct the blob (j, m, {Dj, Ej})
        let blob = concat_hash_array(*id, &msg, &round2_input, &signer.cosigners);

        // Step 4 - rj = H(j,m,{Dj,Ej}_{j in [1...t]})
        let rj = hash_to_field::<<M::G as Group>::Scalar>(&blob);
        if signer.id == *id {
            ri = rj;
        }

        // Step 5 - R_j = D_j + r_j*E_j
        let rj_ej = data.ei * rj;
        let rj = rj_ej + data.di;
        rs.insert(*id, rj);

        // Step 6 - R = R+Rj
        sum_r += rj;
    }

    // Step 7 - c = H(m, R)
    let c = signer
        .challenge_deriver
        .derive_challenge(&msg, signer.vk, sum_r);

    // Step 9 - zi = di + ei*ri + Li*ski*c
    let li = signer.lcoeffs[&signer.id];
    let liski = li * signer.sk_share;
    let liskic = liski * c;

    // Normalize the point.  This math is a little screwy so make sure it's correct.
    if M::group_point_is_negative(sum_r) {
        // Figuring out if it's negative or not is hard.  But once we know, flipping it is easy.
        sum_r = -sum_r;
    }

    let eiri = r1is.small_e * ri;

    // Compute zi = di+ei*ri+Li*ski*c
    let zi = liskic + eiri + r1is.small_d;

    // Step 8 - Record c, R, Rjs
    nsigner.state = Inner::R2(R2InnerState {
        cap_d: r1is.cap_d,
        cap_e: r1is.cap_d,
        commitments: round2_input.clone(),
        msg: msg.to_vec(),
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

fn concat_hash_array<M: Math>(
    id: u32,
    msg: &[u8],
    r2i: &HashMap<u32, Round1Bcast<M>>,
    cosigners: &[u32],
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend(u32::to_be_bytes(id));
    buf.extend(msg);

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

pub fn round_3<M: Math, C: ChallengeDeriver<M>>(
    signer: &SignerState<M, C>,
    round3_input: &HashMap<u32, Round2Bcast<M>>,
) -> Result<(SignerState<M, C>, Round3Bcast<M>), Round3Error> {
    let r2is = match &signer.state {
        Inner::R2(r2is) => r2is,
        _ => return Err(Round3Error::WrongRound(signer.state.legacy_round())),
    };
    let mut nsigner = signer.clone();

    // A bunch of checks we can skip here.

    let r3iu32 = round3_input.len() as u32;

    let signer_c = r2is.c;
    let signer_rs = r2is.cap_rs.clone();
    let signer_msg = r2is.msg.as_slice();

    // Step 1-3
    // Step 1: For j in [1...t]
    let mut z = <<M::G as Group>::Scalar as Field>::zero();
    let negate = M::group_point_is_negative(r2is.sum_r); // TODO verify correctness
    for (id, data) in round3_input {
        let zj = data.zi;
        let vkj = data.vki;

        // Step 2: Verify zj*G = Rj + c*Lj*vkj
        // zj*G
        let zjg = <M::G as Group>::generator() * zj;

        // c*Lj
        let clj = signer_c * signer.lcoeffs[id];

        // cLjvkj
        let cljvkj = vkj * clj;

        // Rj + c*Lj*vkj
        let mut rj = signer_rs[id];

        // see above
        if negate {
            rj = -rj;
        }

        let right = cljvkj + rj;

        // Check equation!
        if zjg != right {
            return Err(Round3Error::ParticipantEquivocate(*id));
        }

        z += zj;
    }

    // Step 4 - 7: Self verify the signature (z, c)
    let zg = <M::G as Group>::generator() * z;
    let cvk = signer.vk * -signer_c; // additive not multiplicative!
    let tmp_r = zg + cvk;

    // Step 6 - c' = H(m, R')
    let tmp_c = signer
        .challenge_deriver
        .derive_challenge(signer_msg, signer.vk, tmp_r);

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
        r: r2is.sum_r,
        z,
        c: signer_c,
        msg: signer_msg.to_vec(),
    };

    Ok((nsigner, r3bc))
}

pub fn verify<M: Math, C: ChallengeDeriver<M>>(
    cderiv: &C,
    vk: M::G,
    msg: &[u8],
    sig: &Signature<M>,
) -> bool {
    // R' = z*G - c*vk
    let zg = <M::G as Group>::generator() * sig.z;
    let cvk = vk * -sig.c; // additive not multiplicative!
    let tmp_r = zg + cvk;

    //c' = H(m, R')
    let tmp_c = cderiv.derive_challenge(msg, vk, tmp_r);

    // Check c == c'
    tmp_c == sig.c
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

        if den.is_zero() {
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
