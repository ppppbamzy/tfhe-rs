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
    let bodies = body_mut.split_into(d);   
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
/// Variant of [`encrypt_crs_glwe_ciphertext`] which assumes that the plaintexts to encrypt are already
/// loaded in the body of the output [`CRSGLWE ciphertext`](`CRSGlweCiphertext`), this is sometimes useful
/// to avoid allocating a [`PlaintextList`] in situ.
///
/// See this [`formal definition`](`GlweCiphertext#glwe-encryption`) for the definition
/// of the GLWE encryption algorithm.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GlweCiphertext creation
/// let crs_glwe_size = CRSGlweSize(2,2);
/// let polynomial_size = PolynomialSize(1024);
/// let crs_glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let crs_glwe_secret_key = allocate_and_generate_new_binary_crs_glwe_secret_key(
///     crs_glwe_size.to_crs_glwe_dimension(),
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create the plaintext
/// let msg = 3u64;
/// let encoded_msg = msg << 60;
///
/// // Create a new GlweCiphertext
/// let mut crs_glwe = CRSGlweCiphertext::new(0u64, crs_glwe_size, polynomial_size, ciphertext_modulus,crs_glwe_size.1);
///
/// // Manually fill the body with the encoded message
/// glwe.get_mut_body().as_mut().fill(encoded_msg);
///
/// encrypt_crs_glwe_ciphertext_assign(
///     &glwe_secret_key,
///     &mut glwe,
///     glwe_modular_std_dev,
///     &mut encryption_generator,
/// );
///
/// let mut output_plaintext_list = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
///
/// decrypt_glwe_ciphertext(&glwe_secret_key, &glwe, &mut output_plaintext_list);
///
/// // Round and remove encoding
/// // First create a decomposer working on the high 4 bits corresponding to our encoding.
/// let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
///
/// output_plaintext_list
///     .iter_mut()
///     .for_each(|elt| *elt.0 = decomposer.closest_representable(*elt.0));
///
/// // Get the raw vector
/// let mut cleartext_list = output_plaintext_list.into_container();
/// // Remove the encoding
/// cleartext_list.iter_mut().for_each(|elt| *elt = *elt >> 60);
/// // Get the list immutably
/// let cleartext_list = cleartext_list;
///
/// // Check we recovered the original message for each plaintext we encrypted
/// cleartext_list.iter().for_each(|&elt| assert_eq!(elt, msg));
/// ```
pub fn encrypt_crs_glwe_ciphertext_assign<Scalar, KeyCont, OutputCont, Gen>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output: &mut GlweCiphertext<OutputCont>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output.glwe_size().to_glwe_dimension() == glwe_secret_key.glwe_dimension(),
        "Mismatch between GlweDimension of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.glwe_size().to_glwe_dimension(),
        glwe_secret_key.glwe_dimension()
    );
    assert!(
        output.polynomial_size() == glwe_secret_key.polynomial_size(),
        "Mismatch between PolynomialSize of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.polynomial_size(),
        glwe_secret_key.polynomial_size()
    );

    let (mut mask, mut body) = output.get_mut_mask_and_body();

    fill_glwe_mask_and_body_for_encryption_assign(
        glwe_secret_key,
        &mut mask,
        &mut body,
        noise_parameters,
        generator,
    );
}
