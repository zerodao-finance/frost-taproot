use std::collections::*;

use super::{
    dkg::{self, ParticipantState},
    math::{self, Field, Group, GroupEncoding, Math, PrimeField},
};

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
    do_dkg_2of2::<math::Secp256k1Math>();
}

use super::thresh;

fn do_test_signers<M: Math>() {
    let (p1, _, p2, _) = do_dkg_2of2::<M>();
    let p1vk = p1.vk.unwrap();

    let lcoeffs1 = thresh::gen_lagrange_coefficients(2, 2, &[1, 2]);
    let lcoeffs2 = lcoeffs1.clone();

    let mut s1 = thresh::SignerState::new(p1, 1, 2, lcoeffs1, vec![1, 2], thresh::UniversalChderiv)
        .expect("test: init signer 1");
    let mut s2 = thresh::SignerState::new(p2, 2, 2, lcoeffs2, vec![1, 2], thresh::UniversalChderiv)
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
        &thresh::UniversalChderiv,
        p1vk,
        &msg,
        &s1_sig
    ));
}

#[test]
fn test_thresh_sign() {
    do_test_signers::<math::Secp256k1Math>();
}
