use digest::Digest;
use elliptic_curve as ec;
pub use ff::{Field, PrimeField};
use rand::SeedableRng;

pub use ec::group::{Curve, Group, GroupEncoding, ScalarMul};
use ec::sec1::ToEncodedPoint;
pub use ec::ScalarArithmetic;

pub trait Math: Clone {
    type F: PrimeField;
    type G: Curve + GroupEncoding + Default + ScalarMul<Self::F>;

    fn scalar_repr_from_bytes(
        buf: &[u8],
    ) -> Option<<<Self::G as Group>::Scalar as PrimeField>::Repr>;
    fn scalar_repr_to_bytes(r: <<Self::G as Group>::Scalar as PrimeField>::Repr) -> Vec<u8>;

    fn group_repr_from_bytes(buf: &[u8]) -> Option<<Self::G as GroupEncoding>::Repr>;
    fn group_repr_to_bytes(r: <Self::G as GroupEncoding>::Repr) -> Vec<u8>;

    /// Returns if the group element is "negative".
    fn group_point_is_negative(e: Self::G) -> bool;
}

// TODO Verify this is a valid way to do it.
pub fn hash_to_curve<G: Group>(buf: &[u8]) -> G {
    let mut rng = hash_to_chacha20(buf);
    G::random(&mut rng)
}

// TODO Verify this is a valid way to do it.
pub fn hash_to_field<F: PrimeField>(buf: &[u8]) -> F {
    let mut rng = hash_to_chacha20(buf);
    F::random(&mut rng)
}

// TODO Verify this is a valid way to do it.
pub fn hash_to_chacha20(buf: &[u8]) -> rand_chacha::ChaCha20Rng {
    let mut comm_digest = sha2::Sha256::default();
    comm_digest.update(&buf);
    let mut comm_hash: [u8; 32] = [0u8; 32];
    let comm_hash_out = comm_digest.finalize();

    for i in 0..32 {
        // FIXME Why do I have to do this byte-by-byte?  Where is copy_from_slice?
        comm_hash[i] = comm_hash_out[i];
    }

    rand_chacha::ChaCha20Rng::from_seed(comm_hash)
}

// Uncomment this when it's ready.
/*struct Curve25519Math;

impl math::Math for Curve25519Math {
    type F = onenine::scalar::Scalar;
    type G = onenine::ristretto::RistrettoPoint;

    fn scalar_repr_from_bytes(buf: &[u8]) -> Option<<Self::F as PrimeField>::Repr> {
        if !buf.len() == 32 {
            return None;
        }

        type FRepr = onenine::scalar::Scalar;

        // why isn't this letting me do `.copy_from_slice`???
        let buf32 = [0; 32];
        for i in 0..32 {
            buf32[i] = buf[i];
        }

        FRepr::from_canonical_bytes(buf32)
    }

    fn scalar_repr_to_bytes(r: <Self::F as PrimeField>::Repr) -> Vec<u8> {
        Vec::from(r.to_bytes())
    }

    fn group_repr_from_bytes(buf: &[u8]) -> Option<<Self::G as GroupEncoding>::Repr> {
        todo!()
    }

    fn group_repr_to_bytes(r: <Self::G as GroupEncoding>::Repr) -> Vec<u8> {
        todo!()
    }
}*/

#[derive(Clone, Debug)]
pub struct Secp256k1Math;

impl Math for Secp256k1Math {
    type F = k256::Scalar;

    type G = k256::ProjectivePoint;

    fn scalar_repr_from_bytes(
        buf: &[u8],
    ) -> Option<<<Self::G as Group>::Scalar as PrimeField>::Repr> {
        // FIXME this is a little more involved than it seems like it needs to be
        k256::FieldBytes::from_exact_iter(buf.iter().copied())
    }

    fn scalar_repr_to_bytes(r: <<Self::G as Group>::Scalar as PrimeField>::Repr) -> Vec<u8> {
        Vec::from(r.as_slice())
    }

    fn group_repr_from_bytes(buf: &[u8]) -> Option<<Self::G as GroupEncoding>::Repr> {
        // FIXME this is a little more involved than it seems like it needs to be
        <Self::G as GroupEncoding>::Repr::from_exact_iter(buf.iter().copied())
    }

    fn group_repr_to_bytes(r: <Self::G as GroupEncoding>::Repr) -> Vec<u8> {
        Vec::from(r.as_slice())
    }

    fn group_point_is_negative(e: Self::G) -> bool {
        // TODO all of these `.unwrap_u8()`s should be replaced with "more" constant-time versions.

        if e.is_identity().unwrap_u8() == 1 {
            return false;
        }

        let aff: k256::AffinePoint = e.to_affine();
        let ep = aff.to_encoded_point(false);
        let y = ep.y().unwrap();

        // Really terrible conversion, surely we can just mask out 1 bit of this and check, right?
        let y_fb = <Self::F as PrimeField>::from_repr(
            k256::FieldBytes::from_exact_iter(y.iter().copied()).unwrap(),
        )
        .unwrap();

        // "high" means zero or positive here, so if it's false then it must be negative.
        y_fb.is_high().unwrap_u8() == 0
    }
}
