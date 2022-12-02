use std::collections::*;

use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use wasm_bindgen::prelude::*;

use krustology_core::frost::math::{Math, Secp256k1Math};

pub use krustology_core::frost::{dkg, serde as fserde};

#[derive(Serialize, Deserialize)]
pub struct DkgR1Output {
    pub state: dkg::R1ParticipantState<Secp256k1Math>,
    pub bcast: DkgR1Bcast,
    pub sends: HashMap<u32, serde_bytes::ByteBuf>,
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct DkgR1Bcast {
    pub verifiers: SerdeFV,
    pub wi: fserde::WrappedScalar<Secp256k1Math>,
    pub ci: fserde::WrappedScalar<Secp256k1Math>,
}

/// Feldman verifier.
#[derive(Serialize, Deserialize)]
pub struct SerdeFV(
    pub vsss_rs::FeldmanVerifier<<Secp256k1Math as Math>::F, <Secp256k1Math as Math>::G>,
);

#[derive(Serialize, Deserialize)]
pub struct DkgR2Output {
    pub state: dkg::R2ParticipantState<Secp256k1Math>,
    pub bcast: dkg::Round2Bcast<Secp256k1Math>,
}

/*
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
*/
