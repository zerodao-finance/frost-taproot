use digest::Digest;
use elliptic_curve as ec;
pub use ff::{Field, PrimeField};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

use ec::group::{Group, GroupEncoding};
use ec::ops::Reduce;

use super::hash::*;
use super::math::{Math, Secp256k1Math};
use super::sig::SchnorrPubkey;

#[derive(Debug, Error)]
pub enum Error {
    #[error("curve point not xonly")]
    PointNotXonly,
}

/// In the Go code this is just a hash-to-field of the serialized inputs, so we
/// could make this totally general and implement it for all `Math`s, it seems.
pub trait ChallengeDeriver<M: Math>: Clone {
    fn derive_challenge(
        &self,
        msg: &[u8; 32],
        pk: M::G,
        r: M::G,
    ) -> Result<<M::G as Group>::Scalar, Error>;
}

#[derive(Clone)]
pub struct UniversalChderiv;

impl<M: Math> ChallengeDeriver<M> for UniversalChderiv {
    fn derive_challenge(
        &self,
        msg: &[u8; 32],
        pk: M::G,
        r: M::G,
    ) -> Result<<M::G as Group>::Scalar, Error> {
        let mut buf = msg.to_vec();
        buf.extend(M::group_repr_to_bytes(pk.to_bytes()));
        buf.extend(M::group_repr_to_bytes(r.to_bytes()));
        Ok(hash_to_field(&buf))
    }
}

/// Taken from k256 code.
const BIP340_CHALLENGE_TAG: &[u8] = b"BIP0340/challenge";

/// Adapted from k256 code.  This is intended to slot into the FROST signing
/// rounds and generate challenges that are specifically compliant with the
/// BIP340 spec (tagged hash, x-only pubkey, etc.), and so it's specialized for
/// secp256k1 instead of being able to work on any curve.
#[derive(Clone, Serialize, Deserialize)]
pub struct Bip340Chderiv;

impl ChallengeDeriver<Secp256k1Math> for Bip340Chderiv {
    fn derive_challenge(
        &self,
        msg_digest: &[u8; 32],
        pk: <Secp256k1Math as Math>::G,
        r: <Secp256k1Math as Math>::G,
    ) -> Result<<<Secp256k1Math as Math>::G as Group>::Scalar, Error> {
        let native_pk = Secp256k1Math::conv_pk(&SchnorrPubkey::from_group_elem(pk));
        let native_vk =
            k256::schnorr::VerifyingKey::try_from(native_pk).map_err(|_| Error::PointNotXonly)?;

        // TODO We might want to consider tweaking this so that we fail properly
        // if the r is incorrect.
        let r_aff: k256::AffinePoint = r.to_affine();
        use elliptic_curve::AffineXCoordinate;
        let rx = r_aff.x();

        let mut buf = Vec::new();
        buf.extend(rx);
        buf.extend(native_vk.to_bytes());
        buf.extend(msg_digest);

        #[cfg(feature = "debug_eprintlns")]
        eprintln!("chderiv sign preimag {}", hex::encode(&buf));

        // basically copied from the k256 code
        let res = tagged_hash(BIP340_CHALLENGE_TAG)
            .chain_update(buf)
            .finalize();
        let e = <k256::Scalar as Reduce<k256::U256>>::from_be_bytes_reduced(res);
        Ok(e)
    }
}

/// Taken from k256 code.
fn tagged_hash(tag: &[u8]) -> Sha256 {
    let tag_hash = Sha256::digest(tag);
    let mut digest = Sha256::new();
    digest.update(&tag_hash);
    digest.update(&tag_hash);
    digest
}
