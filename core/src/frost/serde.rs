use elliptic_curve::{Group, PrimeField};
use group::GroupEncoding;
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeAs, SerializeAs};
use thiserror::Error;
use vsss_rs::Feldman;

use super::math::Math;

#[derive(Debug, Error)]
pub enum SerdeError {
    #[error("bad scalar encoding")]
    BadScalar,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PointSerde(Vec<u8>);

/*impl<G: GroupEncoding> From<G> for PointSerde {
    fn from(value: G) -> Self {
        PointSerde(value.to_bytes().as_ref().to_vec())
    }
}*/

impl<G: GroupEncoding> SerializeAs<G> for PointSerde {
    fn serialize_as<S>(source: &G, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let ps = PointSerde(source.to_bytes().as_ref().to_vec());
        ps.serialize(serializer)
    }
}

impl<G: GroupEncoding> DeserializeAs<G> for PointSerde {
    fn deserialize_as<D>(deserializer: D) -> Result<G, D::Error>
    where
        D: for<'de> serde::Deserializer<'de>,
    {
        todo!()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScalarSerde(Vec<u8>);

/*impl<F: PrimeField> From<F> for ScalarSerde {
    fn from(value: F) -> Self {
        Self(value.to_repr().as_ref().to_vec())
    }
}*/

/*impl<F: PrimeField> TryInto<F> for ScalarSerde {
    type Error;

    fn try_from(value: ScalarSerde) -> Result<Self, Self::Error> {
        todo!()
    }
}*/

/// Terrible hack because TryFromInto is kinda broken for our purposes.
impl<F: PrimeField> SerializeAs<F> for ScalarSerde {
    fn serialize_as<S>(source: &F, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let ss = ScalarSerde(source.to_repr().as_ref().to_vec());
        ss.serialize(serializer)
    }
}

impl<F: PrimeField> DeserializeAs<F> for ScalarSerde {
    fn deserialize_as<D>(deserializer: D) -> Result<F, D::Error>
    where
        D: for<'de> serde::Deserializer<'de>,
    {
        todo!()
    }
}

// primefield -> scalarserde

/// Wrapper for serializing a Feldman.  Maybe we should break it out and have it
/// not just be a single field in-place.
///
/// (t, n)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeldmanSerde(usize, usize);

impl From<vsss_rs::Feldman> for FeldmanSerde {
    fn from(value: vsss_rs::Feldman) -> Self {
        Self(value.t, value.n)
    }
}

impl Into<vsss_rs::Feldman> for FeldmanSerde {
    fn into(self) -> vsss_rs::Feldman {
        Feldman {
            t: self.0,
            n: self.1,
        }
    }
}
