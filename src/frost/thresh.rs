use std::collections::*;

use super::math::*;

enum Error {
    Unimplemented,
}

/// In the Go code this is just a hash-to-field of the serialized inputs, so we
/// could make this totally general and implement it for all `Math`s, it seems.
trait ChallengeDeriver<M: Math> {
    fn derive_challenge(msg: &[u8], pk: M::G, r: M::G) -> Result<M::G, Error>;
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
    cap_d: M::G,
    cap_e: M::G,
    small_d: <M::G as Group>::Scalar,
    small_e: <M::G as Group>::Scalar,

    // Round 2 variables
    commitments: HashMap<u32, Round1Bcast<M>>,
    msg: Vec<u8>,
    c: <M::G as Group>::Scalar,
    cap_rs: HashMap<u32, <M::G as Group>::Scalar>,
    sum_r: M::G,
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

struct Signature<M: Math> {
    z: <M::G as Group>::Scalar,
    c: <M::G as Group>::Scalar,
}
