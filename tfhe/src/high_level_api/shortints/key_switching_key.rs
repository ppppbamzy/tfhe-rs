use super::client_key::GenericShortIntClientKey;
use super::parameters::ShortIntegerParameter;
use super::server_key::GenericShortIntServerKey;
use crate::shortint::parameters::ShortintKeySwitchingParameters;
use crate::shortint::KeySwitchingKey;

use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

/// The key switching key of a short integer type
///
/// A wrapper around `tfhe-shortint` `CastingKey`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericShortIntKeySwitchingKey<P: ShortIntegerParameter> {
    pub(super) key: KeySwitchingKey,
    _marker: PhantomData<P>,
}

impl<P: ShortIntegerParameter> GenericShortIntKeySwitchingKey<P> {
    pub(crate) fn new(
        key_pair_1: (&GenericShortIntClientKey<P>, &GenericShortIntServerKey<P>),
        key_pair_2: (&GenericShortIntClientKey<P>, &GenericShortIntServerKey<P>),
    ) -> Self {
        let ksk_params = ShortintKeySwitchingParameters::new(
            key_pair_2.0.key.parameters.ks_base_log(),
            key_pair_2.0.key.parameters.ks_level(),
        );
        Self {
            key: KeySwitchingKey::new(
                (&key_pair_1.0.key, &key_pair_1.1.key),
                (&key_pair_2.0.key, &key_pair_2.1.key),
                ksk_params,
            ),
            _marker: Default::default(),
        }
    }
}
