use std::collections::*;
use std::ops::Neg;

use rand::Rng;
use thiserror::Error;

use super::dkg;
use super::math::*;

#[derive(Debug, Error)]
enum Error {
    #[error("zero cosigners")]
    ZeroCosigners,

    #[error("threshold out of bounds")]
    ThreshOob,

    #[error("coefficients list mismatch with cosigners list")]
    CoeffsCosignersMismatch,

    #[error("participant only in round {0}")]
    InvalidSetupRound(u32),

    #[error("unimplemented")]
    Unimplemented,
}

/// In the Go code this is just a hash-to-field of the serialized inputs, so we
/// could make this totally general and implement it for all `Math`s, it seems.
trait ChallengeDeriver<M: Math> {
    fn derive_challenge(&self, msg: &[u8], pk: M::G, r: M::G) -> <M::G as Group>::Scalar;
}

struct SignerState<M: Math, C: ChallengeDeriver<M>> {
    round: u32,

    // Setup variables
    id: u32,

    // Other variables (for unimplemented rounds)
    thresh: u32,
    sk_share: <M::G as Group>::Scalar,
    vk_share: M::G,
    vk: M::G,
    lcoeffs: HashMap<u32, <M::G as Group>::Scalar>,
    cosigners: Vec<u32>,
    state: InnerState<M>,
    challenge_deriver: C,
}

struct InnerState<M: Math> {
    // Round 1 variables
    cap_d: Option<M::G>,
    cap_e: Option<M::G>,
    small_d: Option<<M::G as Group>::Scalar>,
    small_e: Option<<M::G as Group>::Scalar>,

    // Round 2 variables
    commitments: Option<HashMap<u32, Round1Bcast<M>>>,
    msg: Option<Vec<u8>>,
    c: Option<<M::G as Group>::Scalar>,
    cap_rs: Option<HashMap<u32, M::G>>,
    sum_r: Option<M::G>,
}

impl<M: Math> Default for InnerState<M> {
    fn default() -> Self {
        InnerState {
            cap_d: None,
            cap_e: None,
            small_d: None,
            small_e: None,
            commitments: None,
            msg: None,
            c: None,
            cap_rs: None,
            sum_r: None,
        }
    }
}

impl<M: Math, C: ChallengeDeriver<M>> SignerState<M, C> {
    fn new(
        info: dkg::ParticipantState<M>,
        id: u32,
        thresh: u32,
        lcoeffs: HashMap<u32, <M::G as Group>::Scalar>,
        cosigners: Vec<u32>,
        cderiv: C,
    ) -> Result<SignerState<M, C>, Error> {
        if info.round != 3 {
            return Err(Error::InvalidSetupRound(info.round));
        }

        if cosigners.is_empty() || lcoeffs.is_empty() {
            return Err(Error::ZeroCosigners);
        }

        if thresh as usize > cosigners.len() {
            return Err(Error::ThreshOob);
        }

        if lcoeffs.len() != cosigners.len() {
            return Err(Error::CoeffsCosignersMismatch);
        }

        if !cosigners.iter().all(|id| lcoeffs.contains_key(id)) {
            return Err(Error::CoeffsCosignersMismatch);
        }

        Ok(SignerState {
            round: 1,
            id,
            thresh,
            sk_share: info.sk_share.expect("setup missing sk_share"),
            vk_share: info.vk_share.expect("setup missing vk_share"),
            vk: info.vk.expect("setup missing vk"),
            lcoeffs,
            cosigners,
            state: InnerState::default(),
            challenge_deriver: cderiv,
        })
    }
}

struct Round1Bcast<M: Math> {
    di: M::G,
    ei: M::G,
}

struct Round2Bcast<M: Math> {
    zi: <M::G as Group>::Scalar,
    vki: M::G,
}

struct Round3Bcast<M: Math> {
    r: M::G,
    z: <M::G as Group>::Scalar,
    c: <M::G as Group>::Scalar,
    msg: Vec<u8>,
}

impl<M: Math> Round3Bcast<M> {
    fn to_sig(&self) -> Signature<M> {
        Signature {
            z: self.z,
            c: self.c,
        }
    }
}

struct Signature<M: Math> {
    z: <M::G as Group>::Scalar,
    c: <M::G as Group>::Scalar,
}

#[derive(Debug, Error)]
enum Round1Error {
    #[error("participant only in round {0}")]
    WrongRound(u32),

    #[error("unimplemented")]
    Unimplemented,
}

fn round_1<M: Math, C: ChallengeDeriver<M>>(
    signer: &mut SignerState<M, C>,
    mut rng: &mut impl Rng,
) -> Result<Round1Bcast<M>, Round1Error> {
    if signer.round != 1 {
        return Err(Round1Error::WrongRound(signer.round));
    }

    // Step 1 - Sample di, ei
    let di = <<M::G as Group>::Scalar as Field>::random(&mut rng);
    let ei = <<M::G as Group>::Scalar as Field>::random(&mut rng);

    // Step 2 - Compute Di, Ei
    let big_di = <M::G as Group>::generator() * di;
    let big_ei = <M::G as Group>::generator() * ei;

    // Update round number
    signer.round = 1;

    // Store di, ei, Di, Ei locally and broadcast Di, Ei
    signer.state.cap_d = Some(big_di);
    signer.state.cap_e = Some(big_ei);
    signer.state.small_d = Some(di);
    signer.state.small_e = Some(ei);

    Ok(Round1Bcast {
        di: big_di,
        ei: big_ei,
    })
}

#[derive(Debug, Error)]
enum Round2Error {
    #[error("participant only in round {0}")]
    WrongRound(u32),

    #[error("message empty")]
    MsgEmpty,

    #[error("input bcast size {0} mismatch with thresh {1}")]
    InputMismatchThresh(u32, u32),

    #[error("unimplemented")]
    Unimplemented,
}

fn round_2<M: Math, C: ChallengeDeriver<M>>(
    signer: &mut SignerState<M, C>,
    msg: Vec<u8>,
    round2_input: HashMap<u32, Round1Bcast<M>>,
) -> Result<Round2Bcast<M>, Round2Error> {
    if signer.round != 1 {
        return Err(Round2Error::WrongRound(signer.round));
    }

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

    // Skipped: Step 2 - Check Dj, Ej on the curve and Store round2Input

    // Store Dj, Ej for further usage.
    // deferred: signer.state.commitments = Some(round2_input);

    // Step 3-6
    let mut r = <M::G as Group>::identity();
    let mut ri = <<M::G as Group>::Scalar as Field>::zero();
    let mut rs = HashMap::<u32, M::G>::new();
    for (id, data) in &round2_input {
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
        r += rj;
    }

    // Step 7 - c = H(m, R)
    let c = signer
        .challenge_deriver
        .derive_challenge(&msg, signer.vk, r);

    // Step 8 - Record c, R, Rjs
    signer.state.c = Some(c);
    signer.state.cap_rs = Some(rs);
    signer.state.sum_r = Some(r);

    // Step 9 - zi = di + ei*ri + Li*ski*c
    let li = signer.lcoeffs[&signer.id];
    let liski = li * signer.sk_share;
    let liskic = liski * signer.state.c.unwrap();

    // TODO Figure out what we have to do with this.  It's just normalizing the point for whatever reason.
    //if signer.state.sum_r.unwrap().is_negative() {
    //negate, so that it's positive
    //}

    let eiri = signer.state.small_e.unwrap() * ri;

    // Compute zi = di+ei*ri+Li*ski*c
    let zi = liskic + eiri + signer.state.small_d.unwrap();

    // Update round number and store message
    signer.round = 2;
    signer.state.msg = Some(msg);

    // Clear small_d and small_e since they're one-time use.
    signer.state.small_d = None;
    signer.state.small_e = None;

    Ok(Round2Bcast {
        zi,
        vki: signer.vk_share,
    })
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
enum Round3Error {
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

fn round_3<M: Math, C: ChallengeDeriver<M>>(
    signer: &mut SignerState<M, C>,
    round3_input: HashMap<u32, Round2Bcast<M>>,
) -> Result<Round3Bcast<M>, Round3Error> {
    if signer.round != 2 {
        return Err(Round3Error::WrongRound(signer.round));
    }

    // A bunch of checks we can skip here.

    let r3iu32 = round3_input.len() as u32;
    if r3iu32 != signer.thresh {
        return Err(Round3Error::InputMismatchThresh(
            round3_input.len() as u32,
            signer.thresh,
        ));
    }

    let signer_c = signer.state.c.expect("signer c value unset");
    let signer_rs = signer
        .state
        .cap_rs
        .as_ref()
        .expect("signer Rs values unset");
    let signer_msg = signer.state.msg.as_ref().expect("signer message unset");

    // Step 1-3
    // Step 1: For j in [1...t]
    let mut z = <<M::G as Group>::Scalar as Field>::zero();
    let negate = false; // see comment above
    for (id, data) in &round3_input {
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
        let rj = signer_rs[id];
        // see comment above on negation
        let right = cljvkj + rj;

        // Check equation!
        if zjg != right {
            return Err(Round3Error::ParticipantEquivocate(*id));
        }

        z += zj;
    }

    // Step 4 - 7: Self verify the signature (z, c)
    let zg = <M::G as Group>::generator() * z;
    let cvk = signer.vk * signer_c.invert().unwrap(); // TODO verify math correct
    let tmp_r = zg + cvk;

    // Step 6 - c' = H(m, R')
    let tmp_c = signer
        .challenge_deriver
        .derive_challenge(signer_msg, signer.vk, tmp_r);

    // Step 7 - Check c = c'
    if tmp_c != signer_c {
        return Err(Round3Error::InvalidSignature);
    }

    // Update round number
    signer.round = 3;

    Ok(Round3Bcast {
        r: signer.state.sum_r.expect("signer sum_r unset"),
        z,
        c: signer_c,
        msg: signer_msg.clone(),
    })
}

fn verify<M: Math, C: ChallengeDeriver<M>>(
    cderiv: &C,
    vk: M::G,
    msg: &[u8],
    sig: &Signature<M>,
) -> bool {
    // R' = z*G - c*vk
    let zg = <M::G as Group>::generator() * sig.z;
    let cinv = sig.c.invert();
    if cinv.is_none().unwrap_u8() == 1 {
        return false;
    }
    let cvk = vk * cinv.unwrap();
    let tmp_r = zg + cvk;

    //c' = H(m, R')
    let tmp_c = cderiv.derive_challenge(msg, vk, tmp_r);

    // Check c == c'
    tmp_c == sig.c
}
