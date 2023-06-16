use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::commons::generators::{EncryptionRandomGenerator, SecretRandomGenerator};
use crate::core_crypto::commons::math::random::{ActivatedRandomGenerator, RandomGenerator};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::crs_glwe_ciphertext::CRSGlweCiphertext;
use crate::core_crypto::prelude::crs_lwe_secret_key::*;
use rayon::prelude::*;
use crate::core_crypto::prelude::polynomial_algorithms::polynomial_wrapping_add_multisum_assign;


/// Convenience function to share the core logic of the CRSGLWE assign encryption between all functions
/// needing it.
pub fn fill_crs_glwe_mask_and_body_for_encryption_assign<KeyCont, BodyCont, MaskCont, Scalar, Gen>(
    crs_glwe_secret_key: & CRSGlweSecretKey<KeyCont>,
    output_mask: &mut  CRSGlweMask<MaskCont>,
    output_body: &mut  CRSGlweBody<BodyCont>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    BodyCont: ContainerMut<Element = Scalar>,
    MaskCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        output_mask.ciphertext_modulus(),
        output_body.ciphertext_modulus(),
        "Mismatched moduli between output_mask ({:?}) and output_body ({:?})",
        output_mask.ciphertext_modulus(),
        output_body.ciphertext_modulus()
    );

    let ciphertext_modulus = output_body.ciphertext_modulus();
    let mask_mut = output_mask.as_mut();
    let body_mut = output_body.as_mut();
    let key_ref = crs_glwe_secret_key.as_ref();
    generator.fill_slice_with_random_mask_custom_mod(mask_mut, ciphertext_modulus);
    generator.unsigned_torus_slice_wrapping_add_random_noise_custom_mod_assign(
        body_mut,
        noise_parameters,
        ciphertext_modulus,
    );

    if !ciphertext_modulus.is_native_modulus() {
        let torus_scaling = ciphertext_modulus.get_scaling_to_native_torus();
        slice_wrapping_scalar_mul_assign(mask_mut, torus_scaling);
        slice_wrapping_scalar_mul_assign(body_mut, torus_scaling);
    }
    let k= key_ref.len()/body_mut.len() ;
    let d= key_ref.len()/mask_mut.len() ;
    let p= key_ref.len()/(k*d);
    // compute the multisum between the secret key and the mask    
    
    let keys = key_ref.split_into(d);// nombre de chunks=d
    let mut bodies = body_mut.split_into(d);   
    bodies.into_iter().zip(keys).for_each(|(body,key_chunk)| {
        let mut body=Polynomial::from_container(body);
        let key_chunk=PolynomialList::from_container(key_chunk,PolynomialSize(p));
        polynomial_wrapping_add_multisum_assign(
            &mut body,
            &output_mask.as_polynomial_list(),
            &key_chunk,
        )
    });//pretty sure the types are wrong
        
}
