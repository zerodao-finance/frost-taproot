use std::collections::*;
use std::hash::Hash;
use std::panic;

use elliptic_curve::ops::Reduce;
use getrandom::getrandom;
use k256::elliptic_curve::PrimeField;
use k256::schnorr::signature::SignatureEncoding;
use krustology_core::frost::challenge::Bip340Chderiv;
use rand::SeedableRng;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use vsss_rs::Shamir;
use wasm_bindgen::prelude::*;

use krustology_core::frost::{dkg, math, math::Secp256k1Math, thresh};

mod frost_secp256k1;
mod utils;

use frost_secp256k1::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

/// This must be called if you want to see rich panic messages.
#[wasm_bindgen]
pub fn krustology_init() {
    panic::set_hook(Box::new(console_error_panic_hook::hook));
}

#[wasm_bindgen]
pub fn add(a: u32, b: u32) -> JsValue {
    let c = a + b;
    println!("{} + {} = {}", a, b, c);
    serde_wasm_bindgen::to_value(&vec![a, b, c]).unwrap()
}

#[wasm_bindgen]
pub fn oops() {
    panic!("fuck!");
}

/// Initializes a DKG session.
#[wasm_bindgen]
pub fn frost_secp256k1_dkg_init(
    id: u32,
    thresh: u32,
    ctx: &[u8],
    other_participants: &[u32],
) -> JsValue {
    let state = match dkg::InitParticipantState::<Secp256k1Math>::new(
        id,
        thresh,
        ctx.to_vec(),
        other_participants.to_vec(),
    ) {
        Ok(st) => st,
        Err(e) => {
            log(&format!("failed: {}", e));
            return JsValue::NULL;
        }
    };

    serde_wasm_bindgen::to_value(&state).unwrap()
}

/// DKG Round 1.
///
/// Secret is a byte blob, like `Vec<u8>`.
#[wasm_bindgen]
pub fn frost_secp256k1_dkg_r1(
    state: JsValue,
    secret: js_sys::Uint8Array,
    rng_seed_entropy: js_sys::Uint8Array,
) -> JsValue {
    let state =
        serde_wasm_bindgen::from_value::<dkg::InitParticipantState<Secp256k1Math>>(state).unwrap();

    let secret_buf: [u8; 32] = secret.to_vec().try_into().unwrap();
    let secret = <k256::Scalar as Reduce<k256::U256>>::from_be_bytes_reduced(secret_buf.into());

    let entropy_buf: [u8; 32] = rng_seed_entropy.to_vec().try_into().unwrap();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(entropy_buf);

    // Actually execute the round.
    let (nstate, bcast, sends) =
        dkg::round_1(&state, secret, &mut rng).expect("krust: frost dkg r1");

    let bc = DkgR1Bcast {
        verifiers: frost_secp256k1::SerdeFV(bcast.verifiers),
        wi: frost_secp256k1::fserde::WrappedScalar(bcast.wi),
        ci: frost_secp256k1::fserde::WrappedScalar(bcast.ci),
    };

    let sends = sends
        .into_iter()
        .map(|(k, v)| {
            // This is not(!) `.value()`, we want the full share buf becuase
            // that's how we have to parse it.
            let buf = serde_bytes::ByteBuf::from(v.0);
            (k, buf)
        })
        .collect::<HashMap<_, _>>();

    let out = DkgR1Output {
        state: nstate,
        bcast: bc,
        sends,
    };
    serde_wasm_bindgen::to_value(&out).unwrap()
}

/// DKG Round 2.
///
/// bcast here is `HashMap<u32, frost_secp256k1::R1Bcast>`
/// p2p_send here are the serialized shamir shares, like `HashMap<u32, Vec<u8>>`.
///
/// Bcasts and sends should be passed as `Vec<(u32, _)>`.
#[wasm_bindgen]
pub fn frost_secp256k1_dkg_r2(state: JsValue, bcasts: JsValue, p2p_sends: JsValue) -> JsValue {
    let state =
        serde_wasm_bindgen::from_value::<dkg::R1ParticipantState<Secp256k1Math>>(state).unwrap();
    let bcasts =
        conv_hashmap_from_list::<u32, dkg::Round1Bcast<Secp256k1Math>, _, _>(bcasts, |v| v)
            .unwrap();
    let sends = conv_hashmap_from_list::<u32, serde_bytes::ByteBuf, _, _>(p2p_sends, |v| {
        vsss_rs::Share(v.into_vec())
    })
    .unwrap();

    let (nstate, nbcast) = dkg::round_2(&state, &bcasts, &sends).expect("krust: frost dkg r2");

    let out = DkgR2Output {
        state: nstate,
        bcast: nbcast,
    };
    serde_wasm_bindgen::to_value(&out).unwrap()
}

/// Takes a hashmap represented as a JS list of 2-element lists, like what Serde
/// would emit for `Vec<(K, V)>`, then passes the V through a transformer.
///
/// Does not check for duplicate keys in the list.
fn conv_hashmap_from_list<K, V, R, X: Fn(V) -> R>(
    value: JsValue,
    xformer: X,
) -> Result<HashMap<K, R>, serde_wasm_bindgen::Error>
where
    K: Hash + Eq + DeserializeOwned,
    V: DeserializeOwned,
{
    let kv_list: Vec<(K, V)> = serde_wasm_bindgen::from_value(value)?;
    let mut map = HashMap::new();

    for (k, v) in kv_list {
        map.insert(k, xformer(v));
    }

    Ok(map)
}

/// Given a DKG r2bcast value, extracts the BIP340 pubkey as a Uint8Array.
#[wasm_bindgen]
pub fn frost_secp256k1_export_bip340_pk(r2bcast: JsValue) -> js_sys::Uint8Array {
    let r2bc = serde_wasm_bindgen::from_value::<dkg::Round2Bcast<Secp256k1Math>>(r2bcast).unwrap();
    let pk = r2bc.to_schnorr_pubkey().to_native();
    match k256::schnorr::VerifyingKey::try_from(pk) {
        Ok(vk) => {
            let bip_buf = vk.to_bytes().to_vec();
            js_sys::Uint8Array::from(bip_buf.as_slice())
        }
        // If I'm right, this should never happen.
        Err(e) => panic!("generated pk is not x-only!!!"),
    }
}

/// Signing session init.
///
/// Each signing session must create a new signer state.
#[wasm_bindgen]
pub fn frost_secp256k1_sign_init(info: JsValue, cosigners: Vec<u32>) -> JsValue {
    let r2state =
        serde_wasm_bindgen::from_value::<dkg::R2ParticipantState<Secp256k1Math>>(info).unwrap();

    let ss = thresh::SignerState::new(&r2state, cosigners, Bip340Chderiv).unwrap();
    serde_wasm_bindgen::to_value(&ss).unwrap()
}

/// Signing Round 1.
#[wasm_bindgen]
pub fn frost_secp256k1_sign_r1(state: JsValue, rng_entropy_buf: js_sys::Uint8Array) -> JsValue {
    let state =
        serde_wasm_bindgen::from_value::<thresh::SignerState<Secp256k1Math, Bip340Chderiv>>(state)
            .unwrap();

    let entropy_buf: [u8; 32] = rng_entropy_buf.to_vec().try_into().unwrap();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(entropy_buf);

    let (ss, bcast) = thresh::round_1(&state, &mut rng).unwrap();

    let out = SignR1Output { state: ss, bcast };
    serde_wasm_bindgen::to_value(&out).unwrap()
}

/// Signing R2.
///
/// r2_input is like HashMap<u32, Round1Bcast<M>>.
#[wasm_bindgen]
pub fn frost_secp256k1_sign_r2(
    state: JsValue,
    msg_hash: js_sys::Uint8Array,
    r2_input: JsValue,
) -> JsValue {
    let state =
        serde_wasm_bindgen::from_value::<thresh::SignerState<Secp256k1Math, Bip340Chderiv>>(state)
            .unwrap();
    let msg_hash: [u8; 32] = msg_hash.to_vec().try_into().unwrap();
    let inp: HashMap<u32, thresh::Round1Bcast<Secp256k1Math>> =
        conv_hashmap_from_list(r2_input, |v| v).unwrap();

    let (ss, bcast) = thresh::round_2(&state, &msg_hash, &inp).unwrap();

    let out = SignR2Output { state: ss, bcast };
    serde_wasm_bindgen::to_value(&out).unwrap()
}

/// Signing R3.
///
/// r3_input is like HashMap<u32, Round2Bcast<M>>.
#[wasm_bindgen]
pub fn frost_secp256k1_sign_r3(state: JsValue, r3_input: JsValue) -> JsValue {
    let state =
        serde_wasm_bindgen::from_value::<thresh::SignerState<Secp256k1Math, Bip340Chderiv>>(state)
            .unwrap();
    let inp: HashMap<u32, thresh::Round2Bcast<Secp256k1Math>> =
        conv_hashmap_from_list(r3_input, |v| v).unwrap();

    let (ss, bcast) = thresh::round_3(&state, &inp).unwrap();

    let out = SignR3Output { state: ss, bcast };
    serde_wasm_bindgen::to_value(&out).unwrap()
}

#[wasm_bindgen]
pub fn frost_secp256k1_export_bip340_sig(r3bc: JsValue) -> js_sys::Uint8Array {
    let r3bc = serde_wasm_bindgen::from_value::<thresh::Round3Bcast<Secp256k1Math>>(r3bc).unwrap();
    let sig: k256::schnorr::Signature = r3bc.to_taproot_sig().to_native();
    let mut out = js_sys::Uint8Array::new_with_length(64);
    out.copy_from(&sig.to_bytes());
    out
}
