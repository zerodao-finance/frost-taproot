use std::collections::*;

use elliptic_curve as ec;
use ff::{Field, PrimeField};
use rand::{rngs::OsRng, CryptoRng, Rng, RngCore};
use thiserror::Error;
use vsss_rs::{Feldman, FeldmanVerifier};
use vsss_rs::{Shamir, Share as ShamirShare};

use ec::group::{Curve, Group, GroupEncoding, ScalarMul};
use ec::ScalarArithmetic;

use super::math::*;

#[derive(Debug, Error)]
pub enum Error {
    #[error("no other participants specified")]
    NoOtherParticipants,

    #[error("unimplemented")]
    Unimplemented,
}

pub struct ParticipantState<M: Math> {
    pub(crate) round: u32,

    // Setup variables
    id: u32,
    feldman: Feldman,
    other_participant_shares: HashMap<u32, ParticipantData<M>>,
    ctx: u8, // not sure what this is, copied from the Go code

    // Round 1 variables
    verifier: Option<FeldmanVerifier<<M::G as Group>::Scalar, M::G>>,
    secret_shares: Option<Vec<ShamirShare>>,

    // Round 2 variables
    pub(crate) sk_share: Option<<M::G as Group>::Scalar>,
    pub(crate) vk: Option<M::G>,
    pub(crate) vk_share: Option<M::G>,
}

struct ParticipantData<M: Math> {
    id: u32,
    share: Option<ShamirShare>,
    verifiers: Option<FeldmanVerifier<<M::G as Group>::Scalar, M::G>>,
}

impl<M: Math> ParticipantState<M> {
    pub fn new(
        id: u32,
        thresh: u32,
        ctx: u8,
        other_participants: Vec<u32>,
    ) -> Result<ParticipantState<M>, Error> {
        if other_participants.is_empty() {
            return Err(Error::NoOtherParticipants);
        }

        let limit = other_participants.len() + 1;

        let feldman = vsss_rs::Feldman {
            n: limit,
            t: thresh as usize,
        };

        let mut other_participant_shares = HashMap::new();
        for opid in other_participants {
            let pd: ParticipantData<M> = ParticipantData {
                id: opid,
                share: None,
                verifiers: None,
            };

            other_participant_shares.insert(opid, pd);
        }

        Ok(ParticipantState {
            round: 1,
            id,
            feldman,
            other_participant_shares,
            ctx,
            sk_share: None,
            vk: None,
            vk_share: None,
            verifier: None,
            secret_shares: None,
        })
    }
}

pub struct Round1Bcast<M: Math> {
    verifiers: FeldmanVerifier<<M::G as Group>::Scalar, M::G>,
    wi: <M::G as Group>::Scalar,
    ci: <M::G as Group>::Scalar,
}

pub struct Round1Result<M: Math> {
    broadcast: Round1Bcast<M>,
    p2p: ShamirShare,
}

pub type Round1Send = HashMap<u32, ShamirShare>;

#[derive(Debug, Error)]
pub enum Round1Error {
    #[error("wrong round {0}")]
    WrongRound(u32),

    #[error("feldman: {0:?}")]
    Feldman(vsss_rs::Error),

    #[error("unimplemented")]
    Unimplemented,
}

pub fn round_1<M: Math, R: RngCore + CryptoRng>(
    participant: &mut ParticipantState<M>,
    secret: <M::G as Group>::Scalar,
    rng: &mut R,
) -> Result<(Round1Bcast<M>, Round1Send), Round1Error> {
    if participant.round != 1 {
        return Err(Round1Error::WrongRound(participant.round));
    }

    // TODO should we check the number of participants?

    // There was some stuff here but due to Rust we don't need it.
    let s = secret;
    let sg = <M::G as Group>::generator() * s;
    eprintln!(
        "secret {} {:?} {}",
        participant.id,
        s,
        hex::encode(sg.to_bytes().as_ref())
    );

    // Step 1 - (Aj0,...Ajt), (xi1,...,xin) <- FeldmanShare(s)
    let (shares, verifier) = participant
        .feldman
        .split_secret::<<M::G as Group>::Scalar, M::G, _>(s, None, rng)
        .map_err(Round1Error::Feldman)?;

    // Step 2 - Sample ki <- Z_q
    let ki = <M::G as Group>::Scalar::random(rng);

    // Step 3 - Compute Ri = ki*G
    let ri = <M::G as Group>::generator() * ki;

    // Step 4 - Compute Ci = H(i, CTX, g^{a_(i,0)}, R_i), where CTX is fixed context string
    let mut buf = Vec::new();
    buf.extend(u32::to_be_bytes(participant.id));
    buf.push(participant.ctx);
    buf.extend(verifier.commitments[0].to_bytes().as_ref());
    buf.push(0xff); // EXTRA
    buf.extend(ri.to_bytes().as_ref());
    eprintln!("round1 {}   {}", participant.id, hex::encode(&buf));

    // Figure out the hash-to-field thing.
    let ci = hash_to_field::<<M::G as Group>::Scalar>(&buf);

    // Step 5 - Compute Wi = ki+a_{i,0}*c_i mod q. Note that a_{i,0} is the secret.
    //
    // The original code is `wi := s.MulAdd(ci, ki)`.
    //
    // The original MulAdd function doc is:
    // ```
    // // MulAdd returns element * y + z mod p
    // MulAdd(y, z Scalar) Scalar
    // ```
    // So we just do this in two steps.
    //
    // There's also this note on the original line:
    //
    // > Note: We have to compute scalar in the following way when using ed25519 curve, rather than scalar := dp.Scalar.Mul(s, Ci)
    // > there is an invalid encoding error when we compute scalar as above.
    let wi = (s * ci) + ki;

    // Step 6 - Broadcast (Ci, Wi, Ci) to other participants
    let r1bc = Round1Bcast {
        verifiers: verifier.clone(),
        wi,
        ci,
    };

    // Step 7 - P2PSend f_i(j) to each participant Pj and keep (i, f_j(i)) for himself
    let mut p2p_send = HashMap::new();
    for oid in participant.other_participant_shares.keys() {
        let share = shares[*oid as usize - 1].clone();
        eprintln!("share {} -> {}: {:?}", participant.id, oid, share);
        p2p_send.insert(*oid, share);
    }

    // Save the things generated in step 1.
    participant.verifier = Some(verifier);
    participant.secret_shares = Some(shares);

    // Update round counter.
    participant.round = 2;

    Ok((r1bc, p2p_send))
}

pub struct Round2Bcast<M: Math> {
    vk: M::G,
    vk_share: M::G,
}

#[derive(Debug, Error)]
pub enum Round2Error {
    #[error("commitment is zero")]
    CommitmentZero,

    #[error("commitment is the identity element")]
    CommitmentIdentity,

    #[error("commitment not on curve")]
    CommitmentNotOnCurve,

    #[error("hash check failed with participant {0}")]
    HashCheckFailed(u32),

    #[error("p2psend table missing participent {0}")]
    PeerSendMissing(u32),

    #[error("feldman verify failed for participant {0}")]
    PeerFeldmanVerifyFailed(u32),
}

pub fn round_2<M: Math>(
    participant: &mut ParticipantState<M>,
    bcast: &HashMap<u32, Round1Bcast<M>>,
    p2psend: HashMap<u32, ShamirShare>,
) -> Result<Round2Bcast<M>, Round2Error> {
    // We should validate Wi and Ci values in Round1Bcats
    for (id, bc) in bcast.iter() {
        if bc.ci.is_zero() {
            return Err(Round2Error::CommitmentZero);
        }

        for com in &bc.verifiers.commitments {
            // TODO Add reporting for the indexes?
            if com.is_identity().unwrap_u8() == 1 {
                return Err(Round2Error::CommitmentIdentity);
            }
        }

        // The Go code also verifies that the point is on the curve, but Rust is
        // better than Go, so it's not possible for our libs to construct an
        // instance of a group element that isn't a valid group element, because
        // obviously lol.
    }

    // Step 2 - for j in 1,...,n
    for (id, bc) in bcast.iter() {
        // Step 3 - if j == i, continue
        if *id == participant.id {
            continue;
        }

        // Step 4 - Check equation c_j = H(j, CTX, A_{j,0}, g^{w_j}*A_{j,0}^{-c_j}
        // Get Aj0
        let aj0 = &bc.verifiers.commitments[0];
        eprintln!(
            "aj0 {} {} {}",
            participant.id,
            id,
            hex::encode(aj0.to_bytes().as_ref())
        );

        // Compute g^{w_j}
        let prod1 = M::G::generator() * bc.wi;

        // Compute A_{j,0}^{-c_j}, and sum.
        let prod2 = *aj0 * -bc.ci; // checked nonzero
        let prod = prod1 + prod2;

        // Now build commitment.
        let mut buf = Vec::new();
        buf.extend(u32::to_be_bytes(*id));
        buf.push(participant.ctx);
        buf.extend(aj0.to_bytes().as_ref());
        buf.push(0xff); // EXTRA
        buf.extend(prod.to_bytes().as_ref());
        eprintln!("round2 {} {} {}", participant.id, id, hex::encode(&buf));

        // Figure out the hash-to-field thing.
        let cj = hash_to_field::<<M::G as Group>::Scalar>(&buf);

        // Check equation.
        if cj != bc.ci {
            return Err(Round2Error::HashCheckFailed(*id));
        } else {
            eprintln!("they match!");
        }

        // Step 5 - FeldmanVerify
        let fji = p2psend
            .get(id)
            .ok_or_else(|| Round2Error::PeerSendMissing(*id))?;

        if !bc.verifiers.verify(fji) {
            return Err(Round2Error::PeerFeldmanVerifyFailed(*id));
        }
    }

    // FIXME convert to soft error?
    let sk_bytes =
        &participant.secret_shares.as_ref().unwrap()[participant.id as usize - 1].value();
    let sk_repr = M::scalar_repr_from_bytes(sk_bytes).expect("shamir share parse as scalar failed");
    let mut sk =
        <M::G as Group>::Scalar::from_repr(sk_repr).expect("shamir share parse as scalar failed");

    let mut vk: M::G = participant.verifier.as_ref().unwrap().commitments[0];

    // Step 6 - Compute signing key share ski = \sum_{j=1}^n xji
    for id in bcast.keys() {
        if *id == participant.id {
            continue;
        }

        // FIXME convert to soft error?
        let t2_repr =
            M::scalar_repr_from_bytes(&p2psend[id].value()).expect("p2psend parse failed");
        let t2 = <M::G as Group>::Scalar::from_repr(t2_repr).expect("p2psend parse failed");
        sk += t2;
    }

    // Step 8 - Compute verification key vk = sum(A_{j,0}), j = 1,...,n
    for (id, bc) in bcast.iter() {
        if *id == participant.id {
            continue;
        }

        vk += bc.verifiers.commitments[0];
    }

    // Store signing key share.
    participant.sk_share = Some(sk);

    // Step 7 - Compute verification key share vki = ski*G and store.
    let vk_share = M::G::generator() * sk;
    participant.vk_share = Some(vk_share);

    // Store verification key.
    participant.vk = Some(vk);

    // Update round number.
    participant.round = 3;

    Ok(Round2Bcast { vk, vk_share })
}
