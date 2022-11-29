use std::collections::*;

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use krustology_core::frost::math::{Math, Secp256k1Math};

/// Feldman verifier.
#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct SerdeFV(
    vsss_rs::FeldmanVerifier<<Secp256k1Math as Math>::F, <Secp256k1Math as Math>::G>,
);

/// Shamir share.
#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct SerdeSS(Vec<u8>);

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct SerdeScalar(Vec<u8>);

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct SerdePoint(Vec<u8>);

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct DkgInitState {
    id: u32,
    feldman: (u32, u32),
    other_shares: HashMap<u32, DkgParticipantData>,
    ctx: Vec<u8>,
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
struct DkgParticipantData {
    share: Option<SerdeSS>,
    verifiers: Option<SerdeFV>,
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct DkgR1State {
    id: u32,
    feldman: (u32, u32),
    other_shares: HashMap<u32, DkgParticipantData>,
    ctx: Vec<u8>,
    verifier: SerdeFV,
    secret_shares: Vec<SerdeSS>,
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct DkgR2State {
    id: u32,
    feldman: (u32, u32),
    sk_share: SerdeScalar,
    vk: SerdePoint,
    vk_share: SerdePoint,
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct DkgR1Output {
    state: DkgR1State,
    bcast: DkgR1Bcast,
    sends: HashMap<u32, SerdeSS>,
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct DkgR1Bcast {
    verifiers: SerdeFV,
    wi: SerdeScalar,
    ci: SerdeScalar,
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct DkgR2Bcast {
    vk: SerdePoint,
    vk_share: SerdePoint,
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct DkgR2Output {
    state: DkgR2State,
    bcast: DkgR2Bcast,
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct SignerState {
    // TODO it's really complicated
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct SignR1Output {
    state: SignerState,
    bcast: SignR1Bcast,
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct SignR1Bcast {
    di: SerdePoint,
    ei: SerdePoint,
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct SignR2Output {
    state: SignerState,
    bcast: SignR2Bcast,
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct SignR2Bcast {
    zi: SerdeScalar,
    vki: SerdePoint,
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct SignR3Output {
    state: SignerState,
    bcast: SignR3Bcast,
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct SignR3Bcast {
    r: SerdePoint,
    z: SerdeScalar,
    c: SerdeScalar,
    msg: Vec<u8>,
}
