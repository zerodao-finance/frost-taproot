use std::collections::*;

use digest::Digest;
use k256::schnorr::signature::hazmat::PrehashVerifier;
use k256::schnorr::signature::{DigestSigner, DigestVerifier, PrehashSignature};
use k256::Secp256k1;
use sha2::Sha256;

use crate::frost::sig::SchnorrPubkey;

use super::sig::TaprootSignature;
use super::{
    bip340,
    challenge::{self, Bip340Chderiv, UniversalChderiv},
    dkg::{self, InitParticipantState},
    math::{self, Field, GroupEncoding, Math, PrimeField, Secp256k1Math},
    sig, thresh,
};

fn do_secp256k1_dkg_2of2() -> (
    dkg::R2ParticipantState<Secp256k1Math>,
    dkg::Round2Bcast<Secp256k1Math>,
    dkg::R2ParticipantState<Secp256k1Math>,
    dkg::Round2Bcast<Secp256k1Math>,
) {
    let ip1 = InitParticipantState::<Secp256k1Math>::new(1, 2, vec![0xff], vec![2])
        .expect("test: init participant 1");
    let ip2 = InitParticipantState::<Secp256k1Math>::new(2, 2, vec![0xff], vec![1])
        .expect("test: init participant 2");

    let mut rng = rand::thread_rng();

    let p1r1_secret = k256::Scalar::random(&mut rng);
    let p2r1_secret = k256::Scalar::random(&mut rng);

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
    p1_s_bytes.extend(p1_sk_share.to_bytes());
    let p1_sk_ss =
        vsss_rs::Share::try_from(p1_s_bytes.as_slice()).expect("test: p1 parse sk_share bytes");
    let mut p2_s_bytes = vec![2];
    let p2_sk_share = r2p2.sk_share();
    p2_s_bytes.extend(p2_sk_share.to_bytes());
    let p2_sk_ss =
        vsss_rs::Share::try_from(p2_s_bytes.as_slice()).expect("test: p2 parse sk_share bytes");

    // Recombine them to the "real" sk.
    let shamir = vsss_rs::Shamir { t: 2, n: 2 };
    let sk = shamir
        .combine_shares::<k256::Scalar>(&[p1_sk_ss, p2_sk_ss])
        .expect("test: parse sk_share");

    // Compute the pubkey and see if it's right.
    let pk = k256::ProjectivePoint::GENERATOR * sk;
    eprintln!(
        "p1 vk   {}\nreal pk {}",
        hex::encode(r2p1.vk().to_bytes()),
        hex::encode(pk.to_bytes())
    );
    assert_eq!(r2p1.vk(), pk);

    eprintln!("=== DKG FINISHED");
    (r2p1, p1r2_bc, r2p2, p2r2_bc)
}

#[test]
fn test_secp256k1_dkg_2of2() {
    // if no panics then it passed
    let _ = do_secp256k1_dkg_2of2();
}

const MSG_STR: &str = "cafebabe13371337deadbeef01234567";

fn do_secp256k1_thresh_sign_2of2(
    msg_hash: &[u8; 32],
) -> (
    SchnorrPubkey<Secp256k1Math>,
    sig::Signature<Secp256k1Math>,
    sig::TaprootSignature<Secp256k1Math>,
) {
    let (p1, _, p2, _) = do_secp256k1_dkg_2of2();
    let p1vk = p1.vk();

    let is1 =
        thresh::SignerState::new(&p1, vec![1, 2], Bip340Chderiv).expect("test: init signer 1");
    let is2 =
        thresh::SignerState::new(&p2, vec![1, 2], Bip340Chderiv).expect("test: init signer 2");

    let mut rng = rand::thread_rng();

    let (r1s1, s1r1_bc) = thresh::round_1(&is1, &mut rng).expect("test: s1 round 1");
    let (r1s2, s2r1_bc) = thresh::round_1(&is2, &mut rng).expect("test: s2 round 1");

    let mut r1_bcast = HashMap::new();
    r1_bcast.insert(1, s1r1_bc);
    r1_bcast.insert(2, s2r1_bc);

    let (r2s1, s1r2_bc) = thresh::round_2(&r1s1, &msg_hash, &r1_bcast).expect("test: s1 round 2");
    let (r2s2, s2r2_bc) = thresh::round_2(&r1s2, &msg_hash, &r1_bcast).expect("test: s2 round 2");

    let mut r2_bcast = HashMap::new();
    r2_bcast.insert(1, s1r2_bc);
    r2_bcast.insert(2, s2r2_bc);

    let (r3s1, s1r3_bc) = thresh::round_3(&r2s1, &r2_bcast).expect("test: s1 round 3");
    let (r3s2, s2r3_bc) = thresh::round_3(&r2s2, &r2_bcast).expect("test: s2 round 3");

    // Assert we get the same signatures on both sides.
    let s1_sig = s1r3_bc.to_sig();
    let s2_sig = s2r3_bc.to_sig();
    assert_eq!(s1_sig, s2_sig);

    eprintln!("=== SIGN FINISHED");
    (p1.to_schnorr_pk(), s1_sig, s1r3_bc.to_taproot_sig())
}

/// This currently fails, we aren't currently compliant with BIP340 schnorr sigs right now.
fn do_secp256k1_thresh_sign_2of2_works_bip340() {
    let msg = hex::decode(MSG_STR).expect("test: parse message");
    let msg_digest = Sha256::digest(&msg);
    let msg_hash = msg_digest.into();

    let (generic_pk, _, taproot_sig) = do_secp256k1_thresh_sign_2of2(&msg_hash);

    eprintln!("generic verification");
    assert!(sig::verify_secp256k1_taproot(
        &generic_pk,
        &msg_hash,
        &taproot_sig
    ));
    eprintln!("== GENERIC OK");

    let native_pk = math::Secp256k1Math::conv_pk(&generic_pk);
    let native_sig = math::Secp256k1Math::conv_tapsig(&taproot_sig);

    let native_bip_vk =
        k256::schnorr::VerifyingKey::try_from(native_pk).expect("test: pk not xonly");

    eprintln!("native verification");
    if let Err(e) = native_bip_vk.verify_prehashed(&msg_hash, &native_sig) {
        panic!("sig failed to verify with k256 verifier: {}", e);
    }
    eprintln!("== NATIVE OK");
}

#[test]
fn test_secp256k1_thresh_sign_2of2_works_bip340_once() {
    do_secp256k1_thresh_sign_2of2_works_bip340();
}

#[test]
fn test_secp256k1_thresh_sign_2of2_works_bip340_many() {
    for _ in 0..500 {
        do_secp256k1_thresh_sign_2of2_works_bip340();
    }
}

#[test]
fn test_secp256k1_simplesign_bip340() {
    let msg = hex::decode(MSG_STR).expect("test: parse message");
    let msg_digest = Sha256::digest(&msg);
    let msg_hash: [u8; 32] = msg_digest.into();

    let mut rng = rand::rngs::OsRng;
    let mut sk = k256::Scalar::random(&mut rng);
    let mut pk = k256::ProjectivePoint::GENERATOR * sk;
    if !bip340::has_even_y(pk.to_affine()) {
        sk = -sk;
        pk = -pk;
    }

    let pk_tap = SchnorrPubkey::from_group_elem(pk);

    let sig = sig::sign_secp256k1_taproot(sk, &msg_hash, &mut rng);

    assert!(sig::verify_secp256k1_taproot(&pk_tap, &msg_hash, &sig));
    println!("passed our verifier");

    let pk_native = <Secp256k1Math as Math>::conv_pk(&pk_tap);
    let sig_native = <Secp256k1Math as Math>::conv_tapsig(&sig);

    let pk_vk = k256::schnorr::VerifyingKey::try_from(pk_native).expect("test: pk not xonly");
    if let Err(e) = pk_vk.verify_prehashed(&msg_hash, &sig_native) {
        panic!("test: sig failed native verify: {}", e);
    }
    println!("passed std verifier");
}

/// Checks that we verify a signature generates from the k256 crate correctly.
#[test]
fn test_secp256k1_verify_taproot() {
    let msg = hex::decode(MSG_STR).expect("test: parse message");
    let msg_pfx = Sha256::new_with_prefix(&msg);
    let msg_digest = Sha256::digest(&msg);
    let msg_hash = msg_digest.into();

    let mut rng = rand::rngs::OsRng;
    let sk_native = k256::schnorr::SigningKey::random(&mut rng);
    let pk_native = sk_native.verifying_key();

    //let sk_generic  = k256::Scalar::from_repr(sk_native.to_bytes()).unwrap();
    let pk_proj = k256::ProjectivePoint::from(pk_native.as_affine());
    let pk_generic = sig::SchnorrPubkey::from_group_elem(pk_proj);

    let sig = sk_native.sign_digest(msg_pfx);
    let sig_buf = sig.to_bytes();
    let sig_generic = sig::TaprootSignature::<Secp256k1Math>::from_bytes(&sig_buf)
        .expect("test: parse sig as generic");

    assert!(sig::verify_secp256k1_taproot(
        &pk_generic,
        &msg_hash,
        &sig_generic
    ));
}

#[ignore]
#[test]
fn test_basic_math_because_idk() {
    let mut rng = rand::rngs::OsRng;

    let mut acc0 = k256::ProjectivePoint::GENERATOR;
    let mut acc0norm = k256::ProjectivePoint::GENERATOR;

    for _ in 0..20 {
        let mut k = k256::Scalar::random(&mut rng);

        let kg = k256::ProjectivePoint::GENERATOR * k;
        let kg_even = bip340::has_even_y(kg.to_affine());
        eprintln!("kg =  {}", bip340::fmt_point(&kg.to_affine()));

        let pa0p = bip340::has_even_y(acc0.to_affine());
        let pa0np = bip340::has_even_y(acc0norm.to_affine());

        acc0 += kg;
        if kg_even {
            acc0norm += kg;
        } else {
            acc0norm += -kg;
        }

        eprintln!(
            "a0 =  {}\na0n=  {}",
            bip340::fmt_point(&acc0.to_affine()),
            bip340::fmt_point(&acc0norm.to_affine()),
        );

        let na0p = bip340::has_even_y(acc0.to_affine());
        let na0np = bip340::has_even_y(acc0norm.to_affine());

        eprintln!(
            "{}.{}={} {}.{}={}\n-----",
            pa0p, kg_even, na0p, pa0np, true, na0np
        );
    }
}
