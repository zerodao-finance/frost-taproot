use elliptic_curve as ec;
pub use ff::{Field, PrimeField};
use rand::SeedableRng;

use ec::group::{Curve, Group, GroupEncoding, ScalarMul};

use super::hash::*;
use super::math::Math;

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
