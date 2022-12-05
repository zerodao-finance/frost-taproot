use std::fmt;

use digest::Digest;
use ec::group::{Curve, Group, GroupEncoding, ScalarMul};
use ec::sec1::ToEncodedPoint;
use elliptic_curve as ec;
use ff::{Field, PrimeField};
use sha2::Sha256;

use super::challenge::*;
use super::math::Math;

#[derive(Clone)]
pub struct SchnorrPubkey<M: Math> {
    pub y: M::G,
}

impl<M: Math> SchnorrPubkey<M> {
    pub fn from_group_elem(e: M::G) -> Self {
        Self { y: e }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        M::group_repr_to_bytes(self.y.to_bytes())
    }

    pub fn from_bytes(&self) -> Option<M::G> {
        unimplemented!()
    }

    pub fn is_x_only(&self) -> bool {
        !M::group_point_is_negative(self.y)
    }
}

#[derive(Clone)]
pub struct Signature<M: Math> {
    /// The "r" in the standard math.
    pub z: <M::G as Group>::Scalar,

    /// The "s" in the standard math.
    pub c: <M::G as Group>::Scalar,
}

impl<M: Math> Signature<M> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = M::scalar_repr_to_bytes(self.z.to_repr());
        let buf2 = M::scalar_repr_to_bytes(self.c.to_repr());
        buf.extend(buf2);
        buf
    }

    pub fn from_bytes(&self, buf: &[u8]) -> Option<Self> {
        if buf.len() % 2 != 0 {
            return None;
        }

        let half = buf.len() / 2;
        let zs = &buf[half..];
        let cs = &buf[..half];
        let zr = M::scalar_repr_from_bytes(zs)?;
        let cr = M::scalar_repr_from_bytes(cs)?;

        let zfr = <<M::G as Group>::Scalar as PrimeField>::from_repr(zr);
        let cfr = <<M::G as Group>::Scalar as PrimeField>::from_repr(cr);

        Some(Self {
            z: if zfr.is_some().into() {
                zfr.unwrap()
            } else {
                return None;
            },
            c: if cfr.is_some().into() {
                cfr.unwrap()
            } else {
                return None;
            },
        })
    }
}

impl<M: Math> fmt::Debug for Signature<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let z_hex = hex::encode(M::scalar_repr_to_bytes(self.z.to_repr()));
        let c_hex = hex::encode(M::scalar_repr_to_bytes(self.c.to_repr()));
        f.write_fmt(format_args!("({},{})", z_hex, c_hex))
    }
}

impl<M: Math> PartialEq for Signature<M> {
    fn eq(&self, other: &Self) -> bool {
        (self.z == other.z) && (self.c == other.c)
    }
}

/// Verifies a signature using a standard challenge deriver.
pub fn verify<M: Math, C: ChallengeDeriver<M>>(
    cderiv: &C,
    pk: &SchnorrPubkey<M>,
    msg: &[u8],
    sig: &Signature<M>,
) -> bool {
    // R' = z*G - c*vk
    let zg = <M::G as Group>::generator() * sig.z;
    let cvk = pk.y * -sig.c; // additive not multiplicative!
    let tmp_r = zg + cvk;

    // c' = H(m, R')
    let msg_digest_ga = Sha256::digest(msg);
    let msg_digest = msg_digest_ga.into();
    let tmp_c = cderiv.derive_challenge(&msg_digest, pk.y, tmp_r);

    // Check c == c'
    tmp_c == sig.c
}
