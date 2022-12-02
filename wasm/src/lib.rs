use std::collections::*;
use std::hash::Hash;
use std::panic;

use frost_secp256k1::DkgR1Bcast;
use frost_secp256k1::DkgR1Output;
use frost_secp256k1::DkgR2Output;
use getrandom::getrandom;
use k256::elliptic_curve::PrimeField;
use k256::schnorr::signature::SignatureEncoding;
use rand::SeedableRng;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use vsss_rs::Shamir;
use wasm_bindgen::prelude::*;

use krustology_core::frost::dkg::Round1Bcast;
use krustology_core::frost::{dkg, math, math::Secp256k1Math, thresh};

mod frost_secp256k1;
mod utils;

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

    let state = serde_wasm_bindgen::to_value(&state).unwrap();
    state
}

/// DKG Round 1.
///
/// Secret is a byte blob, like `Vec<u8>`.
#[wasm_bindgen]
pub fn frost_secp256k1_dkg_r1(state: JsValue, secret: &[u8]) -> JsValue {
    let state =
        serde_wasm_bindgen::from_value::<dkg::InitParticipantState<Secp256k1Math>>(state).unwrap();

    let fb = k256::FieldBytes::from_exact_iter(secret.iter().copied()).unwrap();
    let secret = k256::Scalar::from_repr(fb);
    if secret.is_none().into() {
        panic!("bad secret");
    }

    let secret = secret.unwrap();

    let mut rand_buf = [0; 32];
    getrandom(&mut rand_buf).expect("krust: extract entropy");
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(rand_buf);

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

/// bcast here is `HashMap<u32, frost_secp256k1::R1Bcast>`
/// p2p_send here are the serialized shamir shares, like `HashMap<u32, Vec<u8>>`.
///
/// Bcasts and sends should be passed as `Vec<(u32, _)>`.
#[wasm_bindgen]
pub fn frost_secp256k1_dkg_r2(state: JsValue, bcasts: JsValue, p2p_sends: JsValue) -> JsValue {
    let state =
        serde_wasm_bindgen::from_value::<dkg::R1ParticipantState<Secp256k1Math>>(state).unwrap();
    let bcasts =
        conv_hashmap_from_list::<u32, Round1Bcast<Secp256k1Math>, _, _>(bcasts, |v| v).unwrap();
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

#[wasm_bindgen]
pub fn frost_secp256k1_export_bip340_pk(r2bcast: JsValue) -> js_sys::Uint8Array {
    let r2bc = serde_wasm_bindgen::from_value::<dkg::Round2Bcast<Secp256k1Math>>(r2bcast).unwrap();
    let pk = <Secp256k1Math as math::Math>::conv_pk(r2bc.to_schnorr_pubkey());
    match k256::schnorr::VerifyingKey::try_from(pk) {
        Ok(vk) => {
            let bip_buf = vk.to_bytes().to_vec();
            js_sys::Uint8Array::from(bip_buf.as_slice())
        }
        // If I'm right, this should never happen.
        Err(e) => panic!("generated pk is not x-only!!!"),
    }
}

/*
/// Signing session init.  Each signing session must create a new signer state.
#[wasm_bindgen]
pub fn frost_secp256k1_sign_init(
    info: frost_secp256k1::DkgR2State,
    cosigners: Vec<u32>,
) -> frost_secp256k1::SignerState {
    unimplemented!()
}

/// DKG Round 2.
///
#[wasm_bindgen]
pub fn frost_secp256k1_sign_r1(
    state: frost_secp256k1::SignerState,
    rng_seed: u64,
) -> Result<frost_secp256k1::SignR1Output, String> {
    unimplemented!()
}

/// Signing R2.
///
/// r2_input is like HashMap<u32, Round1Bcast<M>>.
#[wasm_bindgen]
pub fn frost_secp256k1_sign_r2(
    state: frost_secp256k1::SignerState,
    msg: Vec<u8>,
    r2_input: JsValue,
) -> Result<frost_secp256k1::SignR2Output, String> {
    unimplemented!()
}

/// Signing R3.
///
/// r3_input is like HashMap<u32, Round2Bcast<M>>.
#[wasm_bindgen]
pub fn frost_secp256k1_sign_r3(
    state: frost_secp256k1::SignerState,
    r3_input: JsValue,
) -> Result<frost_secp256k1::SignR2Output, String> {
    unimplemented!()
}
*/
