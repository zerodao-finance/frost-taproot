use std::collections::*;

//use curve25519_dalek as onenine;

use curve25519_dalek::scalar::Scalar;
use elliptic_curve::sec1::ToEncodedPoint;

use super::{
    dkg::{self, ParticipantState},
    math::{self, Field, Group, GroupEncoding, PrimeField},
};

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

struct Secp256k1Math;

impl math::Math for Secp256k1Math {
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

fn test_generic_full_dkg_works<M: math::Math>() {
    let mut p0 = ParticipantState::<M>::new(0, 2, 0xff, vec![1]).expect("test: init participant 0");
    let mut p1 = ParticipantState::<M>::new(1, 2, 0xff, vec![0]).expect("test: init participant 1");

    let mut rng = rand::thread_rng();

    let p0r1_secret = <<M::G as Group>::Scalar as Field>::random(&mut rng);
    let p1r1_secret = <<M::G as Group>::Scalar as Field>::random(&mut rng);

    let (p0r1_bc, p0r1_s) = dkg::round_1(&mut p0, p0r1_secret, &mut rng).expect("test: p0 round 1");
    let (p1r1_bc, p1r1_s) = dkg::round_1(&mut p1, p1r1_secret, &mut rng).expect("test: p1 round 1");

    let mut bcast = HashMap::new();
    bcast.insert(0, p0r1_bc);
    bcast.insert(1, p1r1_bc);
    eprintln!("p0s: {:?}\np1s: {:?}", p0r1_s, p1r1_s);

    let mut p0inbox = HashMap::new();
    let mut p1inbox = HashMap::new();
    p0inbox.insert(1u32, p1r1_s[&0].clone());
    p1inbox.insert(0u32, p0r1_s[&1].clone());

    let p1r2_bc = dkg::round_2(&mut p0, &bcast, p0inbox).expect("test: p1 round 2");
    let p2r2_bc = dkg::round_2(&mut p1, &bcast, p1inbox).expect("test: p1 round 2");

    eprintln!("doing things");
}

#[test]
fn test_full_dkg_works() {
    test_generic_full_dkg_works::<Secp256k1Math>();
}

fn prepare_dkg_output<M: math::Math>() -> (ParticipantState<M>, ParticipantState<M>) {
    let mut p0 = ParticipantState::<M>::new(0, 2, 42u8, vec![1]).expect("test: init participant 0");
    let mut p1 = ParticipantState::<M>::new(1, 2, 42u8, vec![0]).expect("test: init participant 1");

    let mut rng = rand::thread_rng();

    let p0r1_secret = <<M::G as Group>::Scalar as Field>::random(&mut rng);
    let p1r1_secret = <<M::G as Group>::Scalar as Field>::random(&mut rng);

    let (p0r1_bc, p0r1_s) = dkg::round_1(&mut p0, p0r1_secret, &mut rng).expect("test: p0 round 1");
    let (p1r1_bc, p1r1_s) = dkg::round_1(&mut p1, p1r1_secret, &mut rng).expect("test: p1 round 1");

    let mut bcast = HashMap::new();
    bcast.insert(0, p0r1_bc);
    bcast.insert(1, p1r1_bc);
    eprintln!("p0s: {:?}\np1s: {:?}", p0r1_s, p1r1_s);

    let mut p0inbox = HashMap::new();
    let mut p1inbox = HashMap::new();
    p0inbox.insert(1u32, p1r1_s[&0].clone());
    p1inbox.insert(0u32, p0r1_s[&1].clone());

    let p1r2_bc = dkg::round_2(&mut p0, &bcast, p0inbox).expect("test: p1 round 2");
    let p2r2_bc = dkg::round_2(&mut p1, &bcast, p1inbox).expect("test: p1 round 2");

    eprintln!("doing things");
    (p0, p1)
}

//#[test]
fn test_prepare() {
    let (p1, p2) = prepare_dkg_output::<Secp256k1Math>();
    eprintln!("ok!");
}
