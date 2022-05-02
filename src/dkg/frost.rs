use std::collections::*;

use digest::{Digest, FixedOutput};
use elliptic_curve as ec;
use ff::{Field, PrimeField};
use rand::SeedableRng;
use rand::{rngs::OsRng, CryptoRng, Rng, RngCore};
use thiserror::Error;
use vsss_rs::{Feldman, FeldmanVerifier};
use vsss_rs::{Shamir, Share as ShamirShare};

use ec::group::{Curve, Group, GroupEncoding, ScalarMul};
use ec::ScalarArithmetic;

trait GroupElem<F: PrimeField>: Curve + GroupEncoding + Default + ScalarMul<F> {}

impl<F: PrimeField, T> GroupElem<F> for T where T: Curve + GroupEncoding + Default + ScalarMul<F> {}

#[derive(Debug, Error)]
pub enum Error {
    #[error("no other participants specified")]
    NoOtherParticipants,

    #[error("unimplemented")]
    Unimplemented,
}

struct ParticipantState<F: PrimeField, G: GroupElem<F>> {
    round: u32,

    // Setup variables
    id: u32,
    feldman: Feldman,
    other_participant_shares: HashMap<u32, ParticipantData<F, G>>,
    ctx: u8, // not sure what this is, copied from the Go code

    // Round 1 variables.
    verifier: Option<FeldmanVerifier<G::Scalar, G>>,
    secret_shares: Option<Vec<ShamirShare>>,

    // Other variables (for unimplemented rounds)
    sk_share: Option<G::Scalar>,
    vk: Option<G>,
    vk_share: Option<G>,
}

struct ParticipantData<F: PrimeField, G: GroupElem<F>> {
    id: u32,
    share: Option<ShamirShare>,
    verifiers: Option<FeldmanVerifier<G::Scalar, G>>,
    _pd: ::std::marker::PhantomData<F>,
}

impl<F: PrimeField, G: GroupElem<F>> ParticipantState<F, G> {
    fn new(
        id: u32,
        thresh: u32,
        ctx: u8,
        other_participants: Vec<u32>,
    ) -> Result<ParticipantState<F, G>, Error> {
        if other_participants.is_empty() {
            return Err(Error::NoOtherParticipants);
        }

        let limit = other_participants.len() + 1;

        let rng = OsRng::default();

        let feldman = vsss_rs::Feldman {
            n: limit,
            t: thresh as usize,
        };

        let mut other_participant_shares = HashMap::new();
        for opid in other_participants {
            let pd: ParticipantData<F, G> = ParticipantData {
                id: opid,
                share: None,
                verifiers: None,
                _pd: ::std::marker::PhantomData,
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

struct Round1Bcast<F: PrimeField, G: GroupElem<F>> {
    verifiers: FeldmanVerifier<G::Scalar, G>,
    wi: G::Scalar,
    ci: G::Scalar,
}

struct Round1Result<F: PrimeField, G: GroupElem<F>> {
    broadcast: Round1Bcast<G::Scalar, G>,
    p2p: ShamirShare,
}

type Round1Send = HashMap<u32, ShamirShare>;

#[derive(Debug, Error)]
enum Round1Error {
    #[error("wrong round {0}")]
    WrongRound(u32),

    #[error("feldman: {0:?}")]
    Feldman(#[from] vsss_rs::Error),

    #[error("unimplemented")]
    Unimplemented,
}

fn round_1<F: PrimeField, G: GroupElem<F>, R: RngCore + CryptoRng>(
    participant: &mut ParticipantState<F, G>,
    secret: G::Scalar,
    rng: &mut R,
) -> Result<(Round1Bcast<F, G>, Round1Send), Round1Error> {
    if participant.round != 1 {
        return Err(Round1Error::WrongRound(participant.round));
    }

    // TODO should we check the number of participants?

    // There was some stuff here but due to Rust we don't need it.
    let s = secret;

    // Step 1 - (Aj0,...Ajt), (xi1,...,xin) <- FeldmanShare(s)
    let (shares, verifier) = participant
        .feldman
        .split_secret::<G::Scalar, G, _>(s, None, rng)?;

    // Step 2 - Sample ki <- Z_q
    let ki = G::Scalar::random(rng);

    // Step 3 - Compute Ri = ki*G
    let ri = ki * G::generator();

    // Step 4 - Compute Ci = H(i, CTX, g^{a_(i,0)}, R_i), where CTX is fixed context string
    let mut buf = Vec::new();
    buf.extend(u32::to_be_bytes(participant.id));
    buf.push(participant.ctx);
    buf.extend(verifier.commitments[0].to_bytes().as_ref());
    buf.extend(ri.to_bytes().as_ref());

    // Figure out the messy hash-to-curve nonsense.
    // TODO Verify this is a valid way to do it.
    let mut comm_digest = sha2::Sha256::default();
    comm_digest.update(&buf);
    let mut comm_hash: [u8; 32] = [0u8; 32];
    let comm_hash_out = comm_digest.finalize();
    for i in 0..32 {
        // FIXME Why do I have to do this byte-by-byte?  Where is copy_from_slice?
        comm_hash[i] = comm_hash_out[i];
    }
    let mut comm_rng = rand_chacha::ChaCha20Rng::from_seed(comm_hash);
    let ci = G::Scalar::random(comm_rng);

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
    let p2p_send = Vec::new();
    for i in 0..participant.other_participant_shares.len() {
        p2p_send.push(shares[i - 1].clone());
    }

    // Save the things generated in step 1.
    participant.verifier = Some(verifier);
    participant.secret_shares = Some(shares);

    // Update round counter.
    participant.round = 2;

    Ok((r1bc, p2p_send))
}
