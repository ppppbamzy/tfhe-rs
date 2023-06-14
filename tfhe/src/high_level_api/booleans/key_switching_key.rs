use super::client_key::FheBoolClientKey;
use super::server_key::FheBoolServerKey;
use crate::boolean::prelude::{BooleanKeySwitchingParameters, KeySwitchingKey};

#[cfg_attr(all(doc, not(doctest)), cfg(feature = "boolean"))]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FheBoolKeySwitchingKey {
    pub(in crate::high_level_api::booleans) key: KeySwitchingKey,
}

impl FheBoolKeySwitchingKey {
    pub(crate) fn new(
        key_pair_1: (&FheBoolClientKey, &FheBoolServerKey),
        key_pair_2: (&FheBoolClientKey, &FheBoolServerKey),
    ) -> Self {
        let ksk_params = unsafe {
            BooleanKeySwitchingParameters::new(
                key_pair_2.0.key.parameters.ks_base_log,
                key_pair_2.0.key.parameters.ks_level,
            )
        };
        Self {
            key: KeySwitchingKey::new(&key_pair_1.0.key, &key_pair_2.0.key, ksk_params),
        }
    }
}
