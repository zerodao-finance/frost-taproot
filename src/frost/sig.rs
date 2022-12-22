use std::fmt;

use elliptic_curve as ec;
use ff::{Field, PrimeField};
use rand::Rng;

use ec::group::{Group, GroupEncoding};
use ec::sec1::ToEncodedPoint;

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

    pub fn from_bytes(&self, buf: &[u8]) -> Option<M::G> {
        if buf.len() != M::G_SIZE {
            return None;
        }

        let yr = M::group_repr_from_bytes(buf)?;
        let yo = <M::G as GroupEncoding>::from_bytes(&yr);

        // Can't use normal things here because of `CtOption`.
        if yo.is_some().into() {
            Some(yo.unwrap())
        } else {
            None
        }
    }

    pub fn is_x_only(&self) -> bool {
        !M::group_point_is_negative(self.y)
    }

    pub fn to_native(&self) -> M::Pk {
        M::conv_pk(self)
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
        let exp_len = M::F_SIZE * 2;

        if buf.len() != exp_len {
            return None;
        }

        let zs = &buf[..M::F_SIZE];
        let cs = &buf[M::F_SIZE..];
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
        let exp_len = M::F_SIZE + M::G_SIZE;

        if buf.len() != exp_len {
            return None;
        }

        // I don't like that this is a vec.
        let mut rbuf = vec![0; (M::F_SIZE + 1)];
        rbuf[0] = 0x02;
        rbuf[1..].copy_from_slice(&buf[..M::G_SIZE]);
        let rr = M::group_repr_from_bytes(&rbuf)?;
        let sbuf = &buf[M::G_SIZE..];
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

    pub fn to_native(&self) -> M::Sig {
        M::conv_tapsig(self)
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
    rng: &mut impl Rng,
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

    #[cfg(feature = "debug_eprintlns")]
    {
        eprintln!("sign e={}", hex::encode(e.to_bytes()));
        eprintln!(
            "sign g^s={} s={}",
            hex::encode(sexp.to_bytes()),
            hex::encode(s.to_bytes())
        );
        eprintln!("sign r={}", hex::encode(r.to_encoded_point(true)));
    }

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
    let sg = k256::ProjectivePoint::GENERATOR * sig.s;
    let ey = pk.y * e;
    let r_v = sg - ey;

    #[cfg(feature = "debug_eprintlns")]
    {
        eprintln!(
            "gnrc g^s={} s={}",
            hex::encode(sg.to_encoded_point(true)),
            hex::encode(sig.s.to_bytes())
        );
        eprintln!(
            "gnrc r ={}\ngnrc rv={}",
            hex::encode(sig.r.to_encoded_point(true)),
            hex::encode(r_v.to_encoded_point(true))
        );
    }

    // assert xs are equal
    let (sigx, _) = bip340::get_xy_coords(sig.r.to_affine());
    let (vfyx, _) = bip340::get_xy_coords(r_v.to_affine());
    sigx == vfyx
}
