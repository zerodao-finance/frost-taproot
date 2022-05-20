use std::collections::*;

//use curve25519_dalek as onenine;

use curve25519_dalek::scalar::Scalar;
use elliptic_curve::sec1::ToEncodedPoint;

use super::{
    dkg::{self, ParticipantState},
    math::{self, Field, Group, GroupEncoding, Math, PrimeField},
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

#[derive(Clone, Debug)]
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

fn do_dkg_2of2<M: math::Math>() -> (
    dkg::ParticipantState<M>,
    dkg::Round2Bcast<M>,
    dkg::ParticipantState<M>,
    dkg::Round2Bcast<M>,
) {
    let mut p1 = ParticipantState::<M>::new(1, 2, 0xff, vec![2]).expect("test: init participant 1");
    let mut p2 = ParticipantState::<M>::new(2, 2, 0xff, vec![1]).expect("test: init participant 2");

    let mut rng = rand::thread_rng();

    let p1r1_secret = <<M::G as Group>::Scalar as Field>::random(&mut rng);
    let p2r1_secret = <<M::G as Group>::Scalar as Field>::random(&mut rng);

    let (p1r1_bc, p1r1_s) = dkg::round_1(&mut p1, p1r1_secret, &mut rng).expect("test: p1 round 1");
    let (p2r1_bc, p2r1_s) = dkg::round_1(&mut p2, p2r1_secret, &mut rng).expect("test: p2 round 1");

    let mut bcast = HashMap::new();
    bcast.insert(1, p1r1_bc);
    bcast.insert(2, p2r1_bc);
    eprintln!("p1s: {:?}\np2s: {:?}", p1r1_s, p2r1_s);

    let mut p1inbox = HashMap::new();
    let mut p2inbox = HashMap::new();
    p1inbox.insert(2u32, p2r1_s[&1].clone());
    p2inbox.insert(1u32, p1r1_s[&2].clone());

    let p1r2_bc = dkg::round_2(&mut p1, &bcast, p1inbox).expect("test: p1 round 2");
    let p2r2_bc = dkg::round_2(&mut p2, &bcast, p2inbox).expect("test: p2 round 2");

    // Make sure they get the same pubkey.
    let p1_vk = p1.vk.unwrap();
    assert_eq!(p1_vk, p2.vk.unwrap());

    // Extract and parse the shares.
    let mut p1_s_bytes = vec![1];
    let p1_sk_share = p1.sk_share.unwrap();
    p1_s_bytes.extend(M::scalar_repr_to_bytes(p1_sk_share.to_repr()).as_slice());
    let p1_sk_ss =
        vsss_rs::Share::try_from(p1_s_bytes.as_slice()).expect("test: p1 parse sk_share bytes");
    let mut p2_s_bytes = vec![2];
    let p2_sk_share = p2.sk_share.unwrap();
    p2_s_bytes.extend(M::scalar_repr_to_bytes(p2_sk_share.to_repr()).as_slice());
    let p2_sk_ss =
        vsss_rs::Share::try_from(p2_s_bytes.as_slice()).expect("test: p2 parse sk_share bytes");

    // Recombine them to the "real" sk.
    let shamir = vsss_rs::Shamir { t: 2, n: 2 };
    let sk = shamir
        .combine_shares::<M::F>(&[p1_sk_ss, p2_sk_ss])
        .expect("test: parse sk_share");

    // Compute the pubkey and see if it's right.
    let pk = <M::G as Group>::generator() * sk;
    eprintln!(
        "p1 vk   {}\nreal pk {}",
        hex::encode(p1_vk.to_bytes()),
        hex::encode(pk.to_bytes())
    );
    assert_eq!(p1_vk, pk);

    (p1, p1r2_bc, p2, p2r2_bc)
}

#[test]
fn test_dkg_2of2_works() {
    do_dkg_2of2::<Secp256k1Math>();
}

use super::thresh;

struct Secp256k1ChallengeDeriver;

impl thresh::ChallengeDeriver<Secp256k1Math> for Secp256k1ChallengeDeriver {
    fn derive_challenge(
        &self,
        msg: &[u8],
        pk: <Secp256k1Math as math::Math>::G,
        r: <Secp256k1Math as math::Math>::G,
    ) -> <<Secp256k1Math as math::Math>::G as Group>::Scalar {
        let mut buf = msg.to_vec();
        buf.extend(Secp256k1Math::group_repr_to_bytes(pk.to_bytes()));
        buf.extend(Secp256k1Math::group_repr_to_bytes(r.to_bytes()));
        math::hash_to_field(&buf)
    }
}

fn do_test_signers() {
    let (p1, _, p2, _) = do_dkg_2of2::<Secp256k1Math>();
    let p1vk = p1.vk.unwrap();

    let lcoeffs1 = thresh::gen_lagrange_coefficients(2, 2, &[1, 2]);
    let lcoeffs2 = lcoeffs1.clone();

    let mut s1 =
        thresh::SignerState::new(p1, 1, 2, lcoeffs1, vec![1, 2], Secp256k1ChallengeDeriver)
            .expect("test: init signer 1");
    let mut s2 =
        thresh::SignerState::new(p2, 2, 2, lcoeffs2, vec![1, 2], Secp256k1ChallengeDeriver)
            .expect("test: init signer 2");

    let mut rng = rand::thread_rng();

    let s1r1_bc = thresh::round_1(&mut s1, &mut rng).expect("test: s1 round 1");
    let s2r1_bc = thresh::round_1(&mut s2, &mut rng).expect("test: s2 round 1");

    let mut r1_bcast = HashMap::new();
    r1_bcast.insert(1, s1r1_bc);
    r1_bcast.insert(2, s2r1_bc);
    let r1_bcast2 = r1_bcast.clone();

    let msg = hex::decode("cafebabe13371337deadbeef01234567").expect("test: parse message");

    let s1r2_bc = thresh::round_2(&mut s1, msg.clone(), r1_bcast).expect("test: s1 round 2");
    let s2r2_bc = thresh::round_2(&mut s2, msg.clone(), r1_bcast2).expect("test: s2 round 2");

    let mut r2_bcast = HashMap::new();
    r2_bcast.insert(1, s1r2_bc);
    r2_bcast.insert(2, s2r2_bc);
    let r2_bcast2 = r2_bcast.clone();

    let s1r3_bc = thresh::round_3(&mut s1, r2_bcast).expect("test: s1 round 3");
    let s2r3_bc = thresh::round_3(&mut s2, r2_bcast2).expect("test: s2 round 3");

    // Assert we get the same signatures on both sides.
    let s1_sig = s1r3_bc.to_sig();
    let s2_sig = s2r3_bc.to_sig();
    assert_eq!(s1_sig, s2_sig);

    // Assert the signature is correct.
    assert!(thresh::verify(
        &Secp256k1ChallengeDeriver,
        p1vk,
        &msg,
        &s1_sig
    ));
}

#[test]
fn test_thresh_sign() {
    do_test_signers();
}
