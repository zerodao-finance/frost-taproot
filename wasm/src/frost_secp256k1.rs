use std::collections::*;

use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use wasm_bindgen::prelude::*;

use frost_taproot::frost::{
    challenge::Bip340Chderiv,
    math::{Math, Secp256k1Math},
};

pub use frost_taproot::frost::{dkg, serde as fserde, thresh};

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

#[derive(Serialize, Deserialize)]
pub struct SignR1Output {
    pub state: thresh::SignerState<Secp256k1Math, Bip340Chderiv>,
    pub bcast: thresh::Round1Bcast<Secp256k1Math>,
}

#[derive(Serialize, Deserialize)]
pub struct SignR2Output {
    pub state: thresh::SignerState<Secp256k1Math, Bip340Chderiv>,
    pub bcast: thresh::Round2Bcast<Secp256k1Math>,
}

#[derive(Serialize, Deserialize)]
pub struct SignR3Output {
    pub state: thresh::SignerState<Secp256k1Math, Bip340Chderiv>,
    pub bcast: thresh::Round3Bcast<Secp256k1Math>,
}
