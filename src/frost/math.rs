use digest::{Digest, FixedOutput};
use elliptic_curve as ec;
pub use ff::{Field, PrimeField};
use rand::SeedableRng;

pub use ec::group::{Curve, Group, GroupEncoding, ScalarMul};
pub use ec::ScalarArithmetic;

pub trait Math {
    type F: PrimeField;
    type G: Curve + GroupEncoding + Default + ScalarMul<Self::F>;

    fn scalar_repr_from_bytes(
        buf: &[u8],
    ) -> Option<<<Self::G as Group>::Scalar as PrimeField>::Repr>;
    fn scalar_repr_to_bytes(r: <<Self::G as Group>::Scalar as PrimeField>::Repr) -> Vec<u8>;

    fn group_repr_from_bytes(buf: &[u8]) -> Option<<Self::G as GroupEncoding>::Repr>;
    fn group_repr_to_bytes(r: <Self::G as GroupEncoding>::Repr) -> Vec<u8>;
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
