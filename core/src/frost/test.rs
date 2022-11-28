use std::collections::*;

use super::{
    dkg::{self, InitParticipantState},
    math::{self, Field, Group, GroupEncoding, Math, PrimeField},
    thresh,
};

fn do_dkg_2of2<M: math::Math>() -> (
    dkg::R2ParticipantState<M>,
    dkg::Round2Bcast<M>,
    dkg::R2ParticipantState<M>,
    dkg::Round2Bcast<M>,
) {
    let ip1 = InitParticipantState::<M>::new(1, 2, vec![0xff], vec![2])
        .expect("test: init participant 1");
    let ip2 = InitParticipantState::<M>::new(2, 2, vec![0xff], vec![1])
        .expect("test: init participant 2");

    let mut rng = rand::thread_rng();

    let p1r1_secret = <<M::G as Group>::Scalar as Field>::random(&mut rng);
    let p2r1_secret = <<M::G as Group>::Scalar as Field>::random(&mut rng);

    let (r1p1, p1r1_bc, p1r1_s) =
        dkg::round_1(&ip1, p1r1_secret, &mut rng).expect("test: p1 round 1");
    let (r1p2, p2r1_bc, p2r1_s) =
        dkg::round_1(&ip2, p2r1_secret, &mut rng).expect("test: p2 round 1");

    let mut bcast = HashMap::new();
    bcast.insert(1, p1r1_bc);
    bcast.insert(2, p2r1_bc);
    eprintln!("p1s: {:?}\np2s: {:?}", p1r1_s, p2r1_s);

    let mut p1inbox = HashMap::new();
    let mut p2inbox = HashMap::new();
    p1inbox.insert(2u32, p2r1_s[&1].clone());
    p2inbox.insert(1u32, p1r1_s[&2].clone());

    let (r2p1, p1r2_bc) = dkg::round_2(&r1p1, &bcast, &p1inbox).expect("test: p1 round 2");
    let (r2p2, p2r2_bc) = dkg::round_2(&r1p2, &bcast, &p2inbox).expect("test: p2 round 2");

    // Make sure they get the same pubkey.
    assert_eq!(r2p1.vk(), r2p2.vk());

    // Extract and parse the shares.
    let mut p1_s_bytes = vec![1];
    let p1_sk_share = r2p1.sk_share();
    p1_s_bytes.extend(M::scalar_repr_to_bytes(p1_sk_share.to_repr()).as_slice());
    let p1_sk_ss =
        vsss_rs::Share::try_from(p1_s_bytes.as_slice()).expect("test: p1 parse sk_share bytes");
    let mut p2_s_bytes = vec![2];
    let p2_sk_share = r2p2.sk_share();
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
        hex::encode(r2p1.vk().to_bytes()),
        hex::encode(pk.to_bytes())
    );
    assert_eq!(r2p1.vk(), pk);

    (r2p1, p1r2_bc, r2p2, p2r2_bc)
}

#[test]
fn test_dkg_2of2_works_secp256k1() {
    do_dkg_2of2::<math::Secp256k1Math>();
}

/*
#[test]
fn test_dkg_2of2_works_curve25519() {
    do_dkg_2of2::<math::Curve25519Math>();
}
 */

fn do_thresh_sign_2of2<M: Math>() {
    let (p1, _, p2, _) = do_dkg_2of2::<M>();
    let p1vk = p1.vk();

    let is1 = thresh::SignerState::new(&p1, vec![1, 2], thresh::UniversalChderiv)
        .expect("test: init signer 1");
    let is2 = thresh::SignerState::new(&p2, vec![1, 2], thresh::UniversalChderiv)
        .expect("test: init signer 2");

    let mut rng = rand::thread_rng();

    let (r1s1, s1r1_bc) = thresh::round_1(&is1, &mut rng).expect("test: s1 round 1");
    let (r1s2, s2r1_bc) = thresh::round_1(&is2, &mut rng).expect("test: s2 round 1");

    let mut r1_bcast = HashMap::new();
    r1_bcast.insert(1, s1r1_bc);
    r1_bcast.insert(2, s2r1_bc);

    let msg = hex::decode("cafebabe13371337deadbeef01234567").expect("test: parse message");

    let (r2s1, s1r2_bc) = thresh::round_2(&r1s1, &msg, &r1_bcast).expect("test: s1 round 2");
    let (r2s2, s2r2_bc) = thresh::round_2(&r1s2, &msg, &r1_bcast).expect("test: s2 round 2");

    let mut r2_bcast = HashMap::new();
    r2_bcast.insert(1, s1r2_bc);
    r2_bcast.insert(2, s2r2_bc);

    let (r3s1, s1r3_bc) = thresh::round_3(&r2s1, &r2_bcast).expect("test: s1 round 3");
    let (r3s2, s2r3_bc) = thresh::round_3(&r2s2, &r2_bcast).expect("test: s2 round 3");

    // Assert we get the same signatures on both sides.
    let s1_sig = s1r3_bc.to_sig();
    let s2_sig = s2r3_bc.to_sig();
    assert_eq!(s1_sig, s2_sig);

    // Assert the signature is correct.
    assert!(thresh::verify(
        &thresh::UniversalChderiv,
        p1vk,
        &msg,
        &s1_sig
    ));
}

#[test]
fn test_thresh_sign_2of2_works_secp256k1() {
    do_thresh_sign_2of2::<math::Secp256k1Math>();
}

/*
#[test]
fn test_thresh_sign_2of2_works_curve25519() {
    do_thresh_sign_2of2::<math::Curve25519Math>();
}
*/
