#![allow(unused_doc_comments)]
#![cfg_attr(fmt, rustfmt::skip)]
#![cfg_attr(doc, feature(doc_auto_cfg))]
#![cfg_attr(doc, feature(doc_cfg))]
#![allow(clippy::bool_assert_comparison)]
#![allow(clippy::assign_op_pattern)]
#![allow(clippy::eq_op)]
#![allow(clippy::assign_op_pattern)]
pub use config::{ConfigBuilder, Config};
pub use global_state::{set_server_key, unset_server_key, with_server_key_as_context};
pub use keys::{generate_keys, ClientKey, ServerKey, PublicKey};
pub use errors::{OutOfRangeError, Error};

#[cfg(test)]
mod tests;

#[cfg(feature = "integer")]
pub use crate::typed_api::integers::{
    FheUint8, FheUint10, FheUint12, FheUint16, FheUint14, GenericInteger, RadixParameters, CrtParameters, FheUint256
};
#[cfg(feature = "shortint")]
pub use crate::typed_api::shortints::{
    FheUint2, FheUint2Parameters, CompressedFheUint2,
    FheUint3, FheUint3Parameters, CompressedFheUint3,
    FheUint4, FheUint4Parameters, CompressedFheUint4,
};
#[cfg(feature = "boolean")]
pub use crate::typed_api::booleans::{
    FheBool, CompressedFheBool, FheBoolParameters,
};
#[macro_use]
mod details;
#[macro_use]
mod global_state;
#[macro_use]
mod keys;
mod config;
mod traits;
mod internal_traits;

/// The tfhe prelude.
pub mod prelude;
pub mod errors;
#[cfg(feature = "integer")]
mod integers;
#[cfg(feature = "shortint")]
mod shortints;
#[cfg(feature = "boolean")]
mod booleans;

pub mod parameters { }
