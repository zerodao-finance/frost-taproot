use std::fmt;

use digest::Digest;
use ec::group::{Curve, Group, GroupEncoding, ScalarMul};
use ec::sec1::ToEncodedPoint;
use elliptic_curve as ec;
use ff::{Field, PrimeField};
use rand::Rng;
use sha2::Sha256;

use super::bip340::{self, has_even_y};
use super::challenge::*;
use super::math::{Math, Secp256k1Math};

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
    pub z: <M::G as Group>::Scalar,
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

        // Can't use normal things here because of `CtOption`.
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

#[derive(Clone)]
pub struct TaprootSignature<M: Math> {
    pub r: M::G,
    pub s: <M::G as Group>::Scalar,
}

impl<M: Math> TaprootSignature<M> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        let rbuf = M::group_repr_to_bytes(self.r.to_bytes());
        #[cfg(debug_assertions)]
        assert_eq!(rbuf.len(), 33);

        let sbuf = M::scalar_repr_to_bytes(self.s.to_repr());
        #[cfg(debug_assertions)]
        assert_eq!(sbuf.len(), 32);

        buf.extend(&rbuf[1..]); // x only
        buf.extend(sbuf);
        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        let mut rbuf = [0; 33];
        rbuf[0] = 0x02;
        rbuf[1..].copy_from_slice(&buf[..32]);
        let rr = M::group_repr_from_bytes(&rbuf)?;
        let sbuf = &buf[32..];
        let sr = M::scalar_repr_from_bytes(sbuf)?;

        let ro = <M::G as GroupEncoding>::from_bytes(&rr);
        let so = <<M::G as Group>::Scalar as PrimeField>::from_repr(sr);

        // Can't use normal things here because of `CtOption`.
        Some(Self {
            r: if ro.is_some().into() {
                ro.unwrap()
            } else {
                return None;
            },
            s: if so.is_some().into() {
                so.unwrap()
            } else {
                return None;
            },
        })
    }
}

/// Verifies a signature using the specified challenge deriver.
pub fn verify<M: Math, C: ChallengeDeriver<M>>(
    cderiv: &C,
    pk: &SchnorrPubkey<M>,
    msg_hash: &[u8; 32],
    sig: &Signature<M>,
) -> bool {
    // R' = z*G - c*vk
    let zg = <M::G as Group>::generator() * sig.z;
    let cvk = pk.y * -sig.c; // additive not multiplicative!
    let tmp_r = zg - cvk;

    // c' = H(m, R')
    let tmp_c = cderiv.derive_challenge(&msg_hash, pk.y, tmp_r);

    // Check c == c'
    tmp_c == sig.c
}

/// Our implementation of taproot schnorr signing so that we can verify our assumptions.
pub fn sign_secp256k1_taproot(
    secret_x: k256::Scalar,
    msg_hash: &[u8; 32],
    mut rng: &mut impl Rng,
) -> TaprootSignature<Secp256k1Math> {
    let p = k256::ProjectivePoint::GENERATOR * secret_x;

    let kprime = k256::Scalar::random(rng);
    let r = k256::ProjectivePoint::GENERATOR * kprime;
    let k = if has_even_y(r.to_affine()) {
        kprime
    } else {
        -kprime
    };

    let e = Bip340Chderiv.derive_challenge(msg_hash, p, r);
    let s = k + (e * secret_x);
    let sexp = k256::ProjectivePoint::GENERATOR * s;

    eprintln!("sign e={}", hex::encode(e.to_bytes()));
    eprintln!(
        "sign g^s={} s={}",
        hex::encode(sexp.to_bytes()),
        hex::encode(s.to_bytes())
    );
    eprintln!("sign r={}", hex::encode(r.to_encoded_point(true)));

    TaprootSignature { r, s }
}

/// Verifies a taprooty signature using the specified challenge deriver.
pub fn verify_secp256k1_taproot(
    pk: &SchnorrPubkey<Secp256k1Math>,
    msg_hash: &[u8; 32],
    sig: &TaprootSignature<Secp256k1Math>,
) -> bool {
    // e = H_c(r || P || m)
    let e = Bip340Chderiv.derive_challenge(msg_hash, pk.y, sig.r);

    // r_v = sG + eP
    let r_v = (k256::ProjectivePoint::GENERATOR * sig.s) - (pk.y * e);

    // assert xs are equal
    let (sigx, _) = bip340::get_xy_coords(sig.r.to_affine());
    let (vfyx, _) = bip340::get_xy_coords(r_v.to_affine());
    sigx == vfyx
}
