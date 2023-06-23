# Reducing the size of keys and ciphertexts
TFHE-rs includes features to reduce the size of both keys and ciphertexts, by compressing them. Without getting into details, the idea is to store only the random seed of the Pseudo Random Number Generator (PRNG). Then, by using the same PRNG and the same seed, the full chain of random values can be reconstructed. 

In the library, entities that can be compressed are prefixed by `Compress`. For instance, the type of a compressed `FheUint256` is `CompressedFheUint256`.


## Compressed ciphertexts
This example shows how to compress a ciphertext encypting messages over 16 bits.

```rust
 use tfhe::prelude::*; 
 use tfhe::{ConfigBuilder, generate_keys, set_server_key, CompressedFheUint16, FheUint16}; 

 fn main() { 
     let config = ConfigBuilder::all_disabled() 
         .enable_default_integers() 
         .build(); 
     let (client_key, _) = generate_keys(config); 

     let clear = 12_837u16; 
     let compressed = CompressedFheUint16::try_encrypt(clear, &client_key).unwrap(); 
     let decompressed = FheUint16::from(compressed); 
     let clear_decompressed: u16 = decompressed.decrypt(&client_key); 
     assert_eq!(clear_decompressed, clear); 
 } 
 ``` 


## Compressed server keys
This example shows how to compress the server keys.

```rust
use tfhe::prelude::*;
use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheUint8, CompressedServerKey, ClientKey};

fn main() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_integers()
        .build();

    let cks = ClientKey::generate(config);
    let compressed_sks = CompressedServerKey::new(&cks);
    let sks = compressed_sks.decompress();

    set_server_key(sks);

    let clear_a = 12u8;
    let a = FheUint8::try_encrypt(clear_a, &cks).unwrap();

    let c = a + 234u8;
    let decrypted: u8 = c.decrypt(&cks);
    assert_eq!(decrypted, clear_a.wrapping_add(234));
}
```


## Compressed public keys
This example shows how to compress the classical public keys.

```rust
use tfhe::prelude::*;
use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheUint8, CompressedPublicKey};

fn main() {
   let config = ConfigBuilder::all_disabled()
        .enable_default_integers()
        .build();
    let (client_key, _) = generate_keys(config);

    let public_key = CompressedPublicKey::new(&client_key);

    let a = FheUint8::try_encrypt(213u8, &public_key).unwrap();
    let clear: u8 = a.decrypt(&client_key);
    assert_eq!(clear, 213u8);
}
```


## Compressed compact public key
This example shows how to use compressed compact public keys. 


```rust
use tfhe::prelude::*;
use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheUint8, CompressedCompactPublicKey};

fn main() {
     let config = ConfigBuilder::all_disabled()
        .enable_custom_integers(
            tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS,
            None,
        )
        .build();
    let (client_key, _) = generate_keys(config);

    let public_key_compressed = CompressedCompactPublicKey::new(&client_key);
    let public_key = public_key_compressed.decompress();
    
    let a = FheUint8::try_encrypt(255u8, &public_key).unwrap();
    let clear: u8 = a.decrypt(&client_key);
    assert_eq!(clear, 255u8);
}
```
