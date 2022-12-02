pub use elliptic_curve::group::{Group, GroupEncoding, ScalarMul};
use elliptic_curve::sec1::ToEncodedPoint;
pub use elliptic_curve::ScalarArithmetic;
use elliptic_curve::{IsHigh, ProjectiveArithmetic};
pub use ff::{Field, PrimeField};

pub trait Math: Clone {
    type C: elliptic_curve::Curve
        + elliptic_curve::AffineArithmetic
        + elliptic_curve::ProjectiveArithmetic;

    type F: PrimeField;
    type G: Group + GroupEncoding + Default + ScalarMul<Self::F>;

    fn scalar_repr_from_bytes(
        buf: &[u8],
    ) -> Option<<<Self::G as Group>::Scalar as PrimeField>::Repr>;
    fn scalar_repr_to_bytes(r: <<Self::G as Group>::Scalar as PrimeField>::Repr) -> Vec<u8>;

    fn group_repr_from_bytes(buf: &[u8]) -> Option<<Self::G as GroupEncoding>::Repr>;
    fn group_repr_to_bytes(r: <Self::G as GroupEncoding>::Repr) -> Vec<u8>;

    /// Returns if the group element is "negative".
    fn group_point_is_negative(e: Self::G) -> bool;
}

#[derive(Clone, Debug)]
pub struct Secp256k1Math;

impl Math for Secp256k1Math {
    type C = k256::Secp256k1;

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
        if e.is_identity().into() {
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
        !bool::from(y_fb.is_high())
    }
}

/*
use curve25519_dalek as onenine;

#[derive(Clone, Debug)]
pub struct Curve25519Math;

impl Math for Curve25519Math {
    type F = onenine::scalar::Scalar;

    type G = onenine::ristretto::RistrettoPoint;

    fn scalar_repr_from_bytes(
        buf: &[u8],
    ) -> Option<<<Self::G as Group>::Scalar as PrimeField>::Repr> {
        GenericArray::<u8, U32>::from_exact_iter(buf.iter().copied())
    }

    fn scalar_repr_to_bytes(r: <<Self::G as Group>::Scalar as PrimeField>::Repr) -> Vec<u8> {
        Vec::from(r.as_slice())
    }

    fn group_repr_from_bytes(buf: &[u8]) -> Option<<Self::G as GroupEncoding>::Repr> {
        GenericArray::<u8, U32>::from_exact_iter(buf.iter().copied())
    }

    fn group_repr_to_bytes(r: <Self::G as GroupEncoding>::Repr) -> Vec<u8> {
        Vec::from(r.as_slice())
    }

    fn group_point_is_negative(_e: Self::G) -> bool {
        false
    }
}
*/
