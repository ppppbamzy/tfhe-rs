pub use base::GenericShortInt;
pub use compressed::CompressedGenericShortint;

pub use r#static::{
    FheUint2, FheUint2Parameters, FheUint3, FheUint3Parameters, FheUint4, FheUint4Parameters,
    CompressedFheUint2, CompressedFheUint3, CompressedFheUint4,
};

use super::client_key::GenericShortIntClientKey;
use super::server_key::GenericShortIntServerKey;
use super::public_key::GenericShortIntPublicKey;

mod base;
mod compressed;
pub(crate) mod r#static;

