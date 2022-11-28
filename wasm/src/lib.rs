use std::collections::*;

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct FrostSecp256k1DkgInitState {
    // TODO
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct FrostSecp256k1DkgR1State {
    // TODO
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct FrostSecp256k1DkgR2State {
    // TODO
}

/// Initializes a DKG session.
#[wasm_bindgen]
pub fn frost_secp256k1_dkg_init(
    id: u32,
    thresh: u32,
    ctx: Vec<u8>,
    other_participants: Vec<u32>,
) -> FrostSecp256k1DkgInitState {
    unimplemented!()
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct FrostSecp256k1R1Output {
    state: FrostSecp256k1DkgR1State,
    bcast: FrostSecp256k1R1Bcast,
    sends: HashMap<u32, Vec<u8>>,
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct FrostSecp256k1R1Bcast {
    // TODO
}

/// DKG Round 1.
///
/// Secret is a byte blob, like `Vec<u8>`.
#[wasm_bindgen]
pub fn frost_secp256k1_dkg_r1(
    state: FrostSecp256k1DkgInitState,
    secret: JsValue,
    rng_seed: u64,
) -> Result<FrostSecp256k1R1Output, String> {
    unimplemented!()
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct FrostSecp256k1R2Bcast {
    // TODO
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct FrostSecp256k1R2Output {
    state: FrostSecp256k1DkgR2State,
    bcast: FrostSecp256k1R2Bcast,
}

/// DKG Round 2.
///
/// bcast here is `HashMap<u32, FrostSecp256k1R1Bcast>`
/// p2p_send here are the serialized shamir shares, like `HashMap<u32, Vec<u8>>`.
#[wasm_bindgen]
pub fn frost_secp256k1_dkg_r2(
    state: FrostSecp256k1DkgR1State,
    bcast: JsValue,
    p2p_send: JsValue,
) -> Result<FrostSecp256k1R2Output, String> {
    unimplemented!()
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct SignerState {
    // TODO
}

/// Signing session init.  Each signing session must create a new signer state.
#[wasm_bindgen]
pub fn frost_secp256k1_sign_init(
    info: FrostSecp256k1DkgR2State,
    cosigners: Vec<u32>,
) -> SignerState {
    unimplemented!()
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct FrostSecp256k1SignR1Output {
    state: SignerState,
    // TODO bcast
}

#[wasm_bindgen]
pub fn frost_secp256k1_sign_r1(
    state: SignerState,
    rng_seed: u64,
) -> Result<FrostSecp256k1SignR1Output, String> {
    unimplemented!()
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct FrostSecp256k1SignR2Output {
    state: SignerState,
    // TODO bcast
}

/// Signing R2.
///
/// r2_input is like HashMap<u32, Round1Bcast<M>>.
#[wasm_bindgen]
pub fn frost_secp256k1_sign_r2(
    state: SignerState,
    msg: Vec<u8>,
    r2_input: JsValue,
) -> Result<FrostSecp256k1SignR2Output, String> {
    unimplemented!()
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct FrostSecp256k1SignR3Output {
    state: SignerState,
    // TODO bcast
}

/// Signing R3.
///
/// r3_input is like HashMap<u32, Round2Bcast<M>>.
#[wasm_bindgen]
pub fn frost_secp256k1_sign_r3(
    state: SignerState,
    r3_input: JsValue,
) -> Result<FrostSecp256k1SignR2Output, String> {
    unimplemented!()
}
