use std::collections::*;

use elliptic_curve as ec;
use ff::{Field, PrimeField};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, TryFromInto};
use thiserror::Error;
use vsss_rs::Share as ShamirShare;
use vsss_rs::{Feldman, FeldmanVerifier};

use ec::group::{Group, GroupEncoding};

use super::serde::*;
use super::{hash, math::*, sig};

#[derive(Debug, Error)]
pub enum Error {
    #[error("no other participants specified")]
    NoOtherParticipants,

    #[error("participant id cannot be zero")]
    ZeroParticipantId,

    #[error("unimplemented")]
    Unimplemented,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitParticipantState<M: Math> {
    // Setup variables
    id: u32,

    #[serde_as(as = "TryFromInto<FeldmanSerde>")]
    feldman: Feldman,
    other_participants: Vec<u32>,
    //other_participant_shares: HashMap<u32, ParticipantData<M>>,
    ctx: Vec<u8>,

    _pd: ::std::marker::PhantomData<M>,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct R1ParticipantState<M: Math> {
    // Setup variables
    id: u32,

    #[serde_as(as = "TryFromInto<FeldmanSerde>")]
    feldman: Feldman,
    other_participants: Vec<u32>,
    //other_participant_shares: HashMap<u32, ParticipantData<M>>,
    ctx: Vec<u8>,

    // Round 1 variables
    verifier: FeldmanVerifier<<M::G as Group>::Scalar, M::G>,
    secret_shares: Vec<ShamirShare>,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct R2ParticipantState<M: Math> {
    // Setup variables
    id: u32,

    #[serde_as(as = "TryFromInto<FeldmanSerde>")]
    feldman: Feldman,
    other_participants: Vec<u32>,
    //other_participant_shares: HashMap<u32, ParticipantData<M>>,
    ctx: Vec<u8>,

    // Round 1 variables
    verifier: FeldmanVerifier<<M::G as Group>::Scalar, M::G>,
    secret_shares: Vec<ShamirShare>,

    // Round 2 variables
    #[serde_as(as = "ScalarSerde")]
    sk_share: <M::G as Group>::Scalar,

    #[serde_as(as = "PointSerde")]
    vk: M::G,

    #[serde_as(as = "PointSerde")]
    vk_share: M::G,
}

impl<M: Math> R2ParticipantState<M> {
    pub fn id(&self) -> u32 {
        self.id
    }

    /// The number of parties the privkey is shared across.
    pub fn group_size(&self) -> u32 {
        self.feldman.n as u32
    }

    /// The number of parties that need to come together to create a signature.
    pub fn group_thresh(&self) -> u32 {
        self.feldman.t as u32
    }

    pub fn sk_share(&self) -> <M::G as Group>::Scalar {
        self.sk_share
    }

    /// The "verification key", which is just a fancy word for a public key
    /// since we're secret sharing it.
    pub fn vk(&self) -> M::G {
        self.vk
    }

    /// Just like .vk(), but wraps it in the nicer container.
    pub fn to_schnorr_pk(&self) -> sig::SchnorrPubkey<M> {
        sig::SchnorrPubkey { y: self.vk }
    }

    pub fn vk_share(&self) -> M::G {
        self.vk_share
    }
}

// TODO Decide how much of this we actually need.
/*#[derive(Clone, Debug, Serialize, Deserialize)]
struct ParticipantData<M: Math> {
    share: ShamirShare,
    verifiers: FeldmanVerifier<<M::G as Group>::Scalar, M::G>,
}*/

impl<M: Math> InitParticipantState<M> {
    pub fn new(
        id: u32,
        thresh: u32,
        ctx: Vec<u8>,
        other_participants: Vec<u32>,
    ) -> Result<InitParticipantState<M>, Error> {
        if other_participants.is_empty() {
            return Err(Error::NoOtherParticipants);
        }

        if id == 0 {
            return Err(Error::ZeroParticipantId);
        }

        let limit = other_participants.len() + 1;

        let feldman = vsss_rs::Feldman {
            n: limit,
            t: thresh as usize,
        };

        /*let mut other_participant_shares = HashMap::new();
        for opid in other_participants {
            let pd: ParticipantData<M> = ParticipantData {
                share: None,
                verifiers: None,
            };

            other_participant_shares.insert(opid, pd);
        }*/

        Ok(InitParticipantState {
            id,
            feldman,
            other_participants,
            //other_participant_shares,
            ctx,
            _pd: ::std::marker::PhantomData,
        })
    }
}

pub struct Round1Bcast<M: Math> {
    verifiers: FeldmanVerifier<<M::G as Group>::Scalar, M::G>,
    wi: <M::G as Group>::Scalar,
    ci: <M::G as Group>::Scalar,
}

pub struct Round1Result<M: Math> {
    pub broadcast: Round1Bcast<M>,
    pub p2p: ShamirShare,
}

pub type Round1Send = HashMap<u32, ShamirShare>;

#[derive(Debug, Error)]
pub enum Round1Error {
    #[error("feldman: {0:?}")]
    Feldman(vsss_rs::Error),

    #[error("unimplemented")]
    Unimplemented,
}

pub fn round_1<M: Math, R: RngCore + CryptoRng>(
    participant: &InitParticipantState<M>,
    secret: <M::G as Group>::Scalar,
    rng: &mut R,
) -> Result<(R1ParticipantState<M>, Round1Bcast<M>, Round1Send), Round1Error> {
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
    buf.extend(u64::to_be_bytes(participant.ctx.len() as u64));
    buf.extend(&participant.ctx);
    buf.extend(verifier.commitments[0].to_bytes().as_ref());
    buf.push(0xff); // EXTRA
    buf.extend(ri.to_bytes().as_ref());
    eprintln!("round1 {}   {}", participant.id, hex::encode(&buf));

    // Figure out the hash-to-field thing.
    let ci = hash::hash_to_field::<<M::G as Group>::Scalar>(&buf);

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
    for oid in &participant.other_participants {
        let share = shares[*oid as usize - 1].clone();
        eprintln!("share {} -> {}: {:?}", participant.id, oid, share);
        p2p_send.insert(*oid, share);
    }

    // Save the things generated in step 1.
    let r1ps = R1ParticipantState {
        id: participant.id,
        feldman: participant.feldman,
        other_participants: participant.other_participants.clone(),
        //other_participant_shares: participant.other_participant_shares.clone(),
        ctx: participant.ctx.clone(),
        verifier,
        secret_shares: shares,
    };

    Ok((r1ps, r1bc, p2p_send))
}

pub struct Round2Bcast<M: Math> {
    pub vk: M::G,
    pub vk_share: M::G,
}

impl<M: Math> Round2Bcast<M> {
    pub fn to_schnorr_pubkey(&self) -> sig::SchnorrPubkey<M> {
        sig::SchnorrPubkey::from_group_elem(self.vk)
    }
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

    #[error("shamir share parse as scalar failed")]
    ShamirShareParseFail,

    #[error("p2p send parse fail from participant {0}")]
    P2PSendParseFail(u32),

    #[error("p2psend table missing participent {0}")]
    PeerSendMissing(u32),

    #[error("feldman verify failed for participant {0}")]
    PeerFeldmanVerifyFailed(u32),
}

pub fn round_2<M: Math>(
    participant: &R1ParticipantState<M>,
    bcast: &HashMap<u32, Round1Bcast<M>>,
    p2psend: &HashMap<u32, ShamirShare>,
) -> Result<(R2ParticipantState<M>, Round2Bcast<M>), Round2Error> {
    // We should validate Wi and Ci values in Round1Bcats
    for (_id, bc) in bcast.iter() {
        if bc.ci.is_zero().into() {
            return Err(Round2Error::CommitmentZero);
        }

        for com in &bc.verifiers.commitments {
            // TODO Add reporting for the indexes?
            if com.is_identity().into() {
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
        buf.extend(u64::to_be_bytes(participant.ctx.len() as u64));
        buf.extend(&participant.ctx);
        buf.extend(aj0.to_bytes().as_ref());
        buf.push(0xff); // EXTRA
        buf.extend(prod.to_bytes().as_ref());
        eprintln!("round2 {} {} {}", participant.id, id, hex::encode(&buf));

        // Figure out the hash-to-field thing.
        let cj = hash::hash_to_field::<<M::G as Group>::Scalar>(&buf);

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

    // Take the bytes from the share and work backwards to get the scalar.
    let sk_bytes = &participant.secret_shares[participant.id as usize - 1].value();
    let sk_repr = M::scalar_repr_from_bytes(sk_bytes).ok_or(Round2Error::ShamirShareParseFail)?;
    let sk_opt = <M::G as Group>::Scalar::from_repr(sk_repr);
    let mut sk = if sk_opt.is_some().into() {
        sk_opt.unwrap()
    } else {
        return Err(Round2Error::ShamirShareParseFail);
    };

    let mut vk: M::G = participant.verifier.commitments[0];

    // Step 6 - Compute signing key share ski = \sum_{j=1}^n xji
    for id in bcast.keys() {
        if *id == participant.id {
            continue;
        }

        // Like above, work backwards from the share that was sent to get the scalar.
        let t2_repr = M::scalar_repr_from_bytes(&p2psend[id].value())
            .ok_or(Round2Error::P2PSendParseFail(*id))?;
        let t2_opt = <M::G as Group>::Scalar::from_repr(t2_repr);
        let t2 = if t2_opt.is_some().into() {
            t2_opt.unwrap()
        } else {
            return Err(Round2Error::P2PSendParseFail(*id));
        };
        sk += t2;
    }

    // Step 8 - Compute verification key vk = sum(A_{j,0}), j = 1,...,n
    for (id, bc) in bcast.iter() {
        if *id == participant.id {
            continue;
        }

        vk += bc.verifiers.commitments[0];
    }

    // Step 7 - Compute verification key share vki = ski*G and store.
    let vk_share = M::G::generator() * sk;

    let r2ps = R2ParticipantState {
        id: participant.id,
        feldman: participant.feldman,
        other_participants: participant.other_participants.clone(),
        //other_participant_shares: participant.other_participant_shares.clone(),
        ctx: participant.ctx.clone(),
        verifier: participant.verifier.clone(),
        secret_shares: participant.secret_shares.clone(),
        sk_share: sk,
        vk,
        vk_share,
    };

    let r2bc = Round2Bcast { vk, vk_share };

    Ok((r2ps, r2bc))
}
