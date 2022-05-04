use elliptic_curve as ec;
pub use ff::{Field, PrimeField};

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
