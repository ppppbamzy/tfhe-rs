# Parallelized Programmable Bootstrapping

The [Programmable Bootstrapping](../getting_started/security_and_cryptography)(PBS) is a sequential operation by nature. However, some [recent results](https://marcjoye.github.io/papers/JP22ternary.pdf) showed that parallelism could be added at the cost of having larger keys. Overall, the performance of the PBS are improved.
In TFHE-rs, since homomorphic operations are already parallelized, activating this feature will improve the performance in the case of parallel-friendly CPUs, or for small input message precision. 

In what follows, an example on how to use the parallelized bootstrapping:

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint32};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigBuilder::all_disabled()
        .enable_custom_integers(
           tfhe::shortint::parameters::PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
           None,
        )
        .build();
        
    let (keys, server_keys) = generate_keys(config);
    set_server_key(server_keys);
    
    let clear_a = 673;
    let clear_b = 6;
    let a = FheUint32::try_encrypt(clear_a, &keys)?;
    let b = FheUint32::try_encrypt(clear_b, &keys)?;

    let c = &a >> &b;
    let decrypted: u32 = c.decrypt(&keys);
    assert_eq!(decrypted, clear_a >> clear_b);

    Ok(())
}
```

# Deterministic Parallelized Programmable Bootstrapping 
By construction, the parallelized PBS might not be deterministic: the result will always be same, but the order of the operations could differ so the output ciphertext might differ. In order to activate the deterministic version, the suffix 'with_deterministic_execution()' should be added to the parameters, as shown in the following example:

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint32};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigBuilder::all_disabled()
        .enable_custom_integers(
           tfhe::shortint::parameters::PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS.with_deterministic_execution(),
           None,
        )
        .build();
        
    let (keys, server_keys) = generate_keys(config);
    set_server_key(server_keys);
    
    let clear_a = 673;
    let clear_b = 6;
    let a = FheUint32::try_encrypt(clear_a, &keys)?;
    let b = FheUint32::try_encrypt(clear_b, &keys)?;

    let c = &a >> &b;
    let decrypted: u32 = c.decrypt(&keys);
    assert_eq!(decrypted, clear_a >> clear_b);

    Ok(())
}
```



