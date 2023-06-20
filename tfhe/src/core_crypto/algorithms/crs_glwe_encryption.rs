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
//use crate::core_crypto::prelude::polynomial_algorithms::polynomial_wrapping_add_multisum_assign;
//use crate::core_crypto::prelude::polynomial_algorithms::polynomial_wrapping_sub_multisum_assign;
use crate::core_crypto::prelude::polynomial_algorithms::*;

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
/// let crs_glwe_size = CRSGlweSize(4,2);
/// let polynomial_size = PolynomialSize(256);
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
///     crs_glwe_size.to_crs_glwe_codimension(),
///     polynomial_size,
///     &mut secret_generator,
/// );
/// //PlaintextList
/// let msg = 0u64;
/// let delta = 56u64;
/// let mut plaintext_list = PlaintextList::new(msg, PlaintextCount(crs_glwe_size.1*polynomial_size.0));
/// let mut list = plaintext_list.as_mut();
/// for (i, el) in list.iter_mut().enumerate(){
/// *el=(*el).wrapping_add((i as u64)<<delta);
/// }
/// // Create a new CRSGlweCiphertext
/// let mut crs_glwe = CRSGlweCiphertext::new(0u64, crs_glwe_size, polynomial_size, ciphertext_modulus);
///
/// // Manually fill the body with the encoded message
/// 
/// let mut body_mut_list = crs_glwe.get_mut_body();
/// let mut body_mut = body_mut_list.as_mut();
/// body_mut.copy_from_slice(list);
/// //body_mut.into_iter().zip(list).for_each(|(body,word)| {
/// //    *body = (*body).wrapping_add(*word);
/// //} );
///  
/// encrypt_crs_glwe_ciphertext_assign(
///     &crs_glwe_secret_key,
///     &mut crs_glwe,
///     crs_glwe_modular_std_dev,
///     &mut encryption_generator,
/// );
///
/// let mut output_plaintext_list = PlaintextList::new(0u64, PlaintextCount(crs_glwe_size.1*polynomial_size.0));
/// 
/// decrypt_crs_glwe_ciphertext(&crs_glwe_secret_key, &crs_glwe, &mut output_plaintext_list);
///
/// // Round and remove encoding
/// // First create a decomposer working on the high X bits corresponding to our encoding.
/// let decomposer = SignedDecomposer::new(DecompositionBaseLog((64-delta) as usize), DecompositionLevelCount(1));
///
/// output_plaintext_list
///     .iter_mut()
///     .for_each(|elt| *elt.0 = decomposer.closest_representable(*elt.0));
///
/// // Get the raw vector
/// let mut cleartext_list = output_plaintext_list.into_container();
/// // Remove the encoding
/// cleartext_list.iter_mut().for_each(|elt| *elt = *elt >> delta);
/// // Get the list immutably
/// let cleartext_list = cleartext_list;
///
/// // Check we recovered the original message for each plaintext we encrypted
/// cleartext_list.iter().for_each(|&elt| println!("{}",elt) );
/// panic!();
/// ```
pub fn encrypt_crs_glwe_ciphertext_assign<Scalar, KeyCont, OutputCont, Gen>(
    crs_glwe_secret_key: &CRSGlweSecretKey<KeyCont>,
    output: &mut CRSGlweCiphertext<OutputCont>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output.crs_glwe_size().to_crs_glwe_dimension() == crs_glwe_secret_key.crs_glwe_dimension(),
        "Mismatch between GlweDimension of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.crs_glwe_size().to_crs_glwe_dimension(),
        crs_glwe_secret_key.crs_glwe_dimension()
    );
    //* 
    assert!(
        output.polynomial_size() == crs_glwe_secret_key.polynomial_size(),
        "Mismatch between PolynomialSize of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.polynomial_size(),
        crs_glwe_secret_key.polynomial_size()
    );
    // */
    let (mut mask, mut body) = output.get_mut_mask_and_body();

    fill_crs_glwe_mask_and_body_for_encryption_assign(
        crs_glwe_secret_key,
        &mut mask,
        &mut body,
        noise_parameters,
        generator,
    );
}

/// Decrypt a [`CRSGLWE ciphertext`](`CRSGlweCiphertext`) in a (scalar) plaintext list.
///
/// See [`encrypt_crs_glwe_ciphertext`] for usage.
///
/// # Formal Definition
///
/// See this [`formal definition`](`CRSGlweCiphertext#crs_glwe-decryption`) for the definition
/// of the CRSGLWE decryption algorithm.
pub fn decrypt_crs_glwe_ciphertext<Scalar, KeyCont, InputCont, OutputCont>(
    crs_glwe_secret_key: &CRSGlweSecretKey<KeyCont>,
    input_crs_glwe_ciphertext: &CRSGlweCiphertext<InputCont>,
    output_plaintext_list: &mut PlaintextList<OutputCont>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    /*
    assert!(
        output_plaintext_list.plaintext_count().0 == (input_crs_glwe_ciphertext.polynomial_size().0*input_crs_glwe_ciphertext.crs_glwe_size().1),
        "Mismatched output PlaintextCount {:?} and input PolynomialSize {:?}*{:?}",
        output_plaintext_list.plaintext_count(),
        input_crs_glwe_ciphertext.polynomial_size(),
        input_crs_glwe_ciphertext.crs_glwe_size()
    );
    // */
    assert!(
        crs_glwe_secret_key.crs_glwe_dimension() == input_crs_glwe_ciphertext.crs_glwe_size().to_crs_glwe_dimension(),
        "Mismatched CRSGlweDimension between crs_glwe_secret_key {:?} and input_crs_glwe_ciphertext {:?}",
        crs_glwe_secret_key.crs_glwe_dimension(),
        input_crs_glwe_ciphertext.crs_glwe_size().to_crs_glwe_dimension()
    );
    //* 
    assert!(
        crs_glwe_secret_key.polynomial_size() == input_crs_glwe_ciphertext.polynomial_size(),
        "Mismatched PolynomialSize between crs_glwe_secret_key {:?} and input_crs_glwe_ciphertext {:?}",
        crs_glwe_secret_key.polynomial_size(),
        input_crs_glwe_ciphertext.polynomial_size()
    );
    // */ 
    let ciphertext_modulus = input_crs_glwe_ciphertext.ciphertext_modulus();

    let (mask, body) = input_crs_glwe_ciphertext.get_mask_and_body();
    let mask_ref = mask.as_ref();
    let body_ref = body.as_ref();
    let key_ref = crs_glwe_secret_key.as_ref();
    output_plaintext_list
        .as_mut()
        .copy_from_slice(body_ref);
    //let output_ref  =output_plaintext_list.as_ref(); 
    let output_mut  =output_plaintext_list.as_mut(); 
    
    let k= key_ref.len()/body_ref.len() ;// could use size()
    let d= key_ref.len()/mask_ref.len() ;
    let p= key_ref.len()/(k*d);
    // compute the multisum between the secret key and the mask    
    
    let keys = key_ref.split_into(d);// nombre de chunks=d
    let mask_list =PolynomialList::from_container(mask_ref,PolynomialSize(p)); 
    let output_pol_list =output_mut.split_into(d);
     // a refaire sur le masque 
     output_pol_list.into_iter().zip(keys).for_each(|(out,key_chunk)| {
        let key_chunk=PolynomialList::from_container(key_chunk,PolynomialSize(p));
        let mut out=Polynomial::from_container(out);
        polynomial_wrapping_sub_multisum_assign(
            & mut out,
            &mask_list,
            &key_chunk,
        );
    });    
    if !ciphertext_modulus.is_native_modulus() {
        slice_wrapping_scalar_div_assign(
            output_plaintext_list.as_mut(),
            ciphertext_modulus.get_scaling_to_native_torus(),
        );
    }
    
}
