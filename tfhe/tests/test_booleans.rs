#![cfg(feature = "boolean")]
#![allow(clippy::bool_assert_comparison)]
#![allow(clippy::assign_op_pattern)]
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};

#[test]
fn test_and() {
    let config = ConfigBuilder::all_disabled().enable_default_bool().build();
    let (my_keys, server_keys) = generate_keys(config);
    set_server_key(server_keys);

    let a = FheBool::encrypt(true, &my_keys);
    let b = FheBool::encrypt(false, &my_keys);

    let c = a & b;
    let clear_res = c.decrypt(&my_keys);
    assert_eq!(clear_res, false);
}
