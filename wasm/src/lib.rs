use std::collections::*;

use wasm_bindgen::prelude::*;

mod frost_secp256k1;

/// Initializes a DKG session.
#[wasm_bindgen]
pub fn frost_secp256k1_dkg_init(
    id: u32,
    thresh: u32,
    ctx: Vec<u8>,
    other_participants: Vec<u32>,
) -> frost_secp256k1::DkgInitState {
    unimplemented!()
}

/// DKG Round 1.
///
/// Secret is a byte blob, like `Vec<u8>`.
#[wasm_bindgen]
pub fn frost_secp256k1_dkg_r1(
    state: frost_secp256k1::DkgInitState,
    secret: JsValue,
    rng_seed: u64,
) -> Result<frost_secp256k1::DkgR1Output, String> {
    unimplemented!()
}
/// bcast here is `HashMap<u32, frost_secp256k1::R1Bcast>`
/// p2p_send here are the serialized shamir shares, like `HashMap<u32, Vec<u8>>`.
#[wasm_bindgen]
pub fn frost_secp256k1_dkg_r2(
    state: frost_secp256k1::DkgR1State,
    bcast: JsValue,
    p2p_send: JsValue,
) -> Result<frost_secp256k1::DkgR2Output, String> {
    unimplemented!()
}

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
