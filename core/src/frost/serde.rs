use std::fmt::Display;

use digest::typenum::Gr;
use elliptic_curve::{
    group::GroupEncoding,
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
    AffineArithmetic, AffinePoint, Curve, FieldBytes, FieldSize, Group, PrimeField,
};
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{serde_as, DeserializeAs, SerializeAs};
use thiserror::Error;
use vsss_rs::Feldman;

use super::math::Math;

#[derive(Debug, Error)]
pub enum SerdeError {
    #[error("bad scalar encoding")]
    BadScalar,

    #[error("bad point encoding")]
    BadPoint,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WrappedPoint<M: Math>(#[serde_as(as = "Marshal<PointSerde<M>>")] pub M::G);

/*impl<M: Math> Into<M::G> for WrappedPoint<M> {
    fn into(self) -> M::G {
        self.0
    }
}

impl<M: Math> From<M::G> for WrappedPoint<M> {
    fn from(value: M::G) -> Self {
        Self(value)
    }
}*/

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WrappedScalar<M: Math>(
    #[serde_as(as = "Marshal<ScalarSerde<M>>")] pub <M::G as Group>::Scalar,
);

/*impl<M: Math> Into<<M::G as Group>::Scalar> for WrappedScalar<M> {
    fn into(self) -> <M::G as Group>::Scalar {
        self.0
    }
}

impl<M: Math> From<<M::G as Group>::Scalar> for WrappedScalar<M> {
    fn from(value: <M::G as Group>::Scalar) -> Self {
        Self(value)
    }
}*/

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PointSerde<M: Math>(
    Vec<u8>,
    #[serde(skip, default)] ::std::marker::PhantomData<M>,
);

impl<M: Math> MarshalFor<M::G> for PointSerde<M> {
    fn conv_to(value: &M::G) -> Self {
        PointSerde(
            value.to_bytes().as_ref().to_vec(),
            ::std::marker::PhantomData,
        )
    }

    fn conv_from(value: Self) -> Result<M::G, SerdeError> {
        let repr = M::group_repr_from_bytes(&value.0).ok_or(SerdeError::BadPoint)?;
        let parsed = <M::G as GroupEncoding>::from_bytes(&repr);

        if parsed.is_some().into() {
            Ok(parsed.unwrap())
        } else {
            Err(SerdeError::BadPoint)
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScalarSerde<M: Math>(
    Vec<u8>,
    #[serde(skip, default)] ::std::marker::PhantomData<M>,
);

impl<M: Math> MarshalFor<<M::G as Group>::Scalar> for ScalarSerde<M> {
    fn conv_to(value: &<M::G as Group>::Scalar) -> Self {
        ScalarSerde(
            value.to_repr().as_ref().to_vec(),
            ::std::marker::PhantomData,
        )
    }

    fn conv_from(value: Self) -> Result<<M::G as Group>::Scalar, SerdeError> {
        let repr = M::scalar_repr_from_bytes(&value.0).ok_or(SerdeError::BadScalar)?;
        let parsed = <M::G as Group>::Scalar::from_repr(repr);

        if parsed.is_some().into() {
            Ok(parsed.unwrap())
        } else {
            Err(SerdeError::BadPoint)
        }
    }
}

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

/// If a type implements this trait it's declaring that it can be used as a
/// marshal for another type that it's impled for in order to customize the
/// serialize representation more flexibly or provide serialization impls for
/// foreign types without the ability to have `From`/`Into` impls for.
pub trait MarshalFor<T> {
    fn conv_to(value: &T) -> Self;
    fn conv_from(value: Self) -> Result<T, SerdeError>;
}

pub struct Marshal<T>(::std::marker::PhantomData<T>);

impl<T, U> SerializeAs<T> for Marshal<U>
where
    U: MarshalFor<T>,
    U: Serialize,
{
    fn serialize_as<S>(source: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        U::conv_to(source).serialize(serializer)
    }
}

impl<'de, T, U> DeserializeAs<'de, T> for Marshal<U>
where
    U: MarshalFor<T>,
    U: Deserialize<'de>,
{
    fn deserialize_as<D>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
    {
        U::conv_from(U::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}
