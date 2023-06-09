//! Module containing primitives pertaining to LWE trace pacling keyswitch.

use crate::core_crypto::algorithms::glwe_keyswitch::*;
use crate::core_crypto::algorithms::polynomial_algorithms::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Apply a trace packing keyswitch on an input [`LWE ciphertext list`](`LweCiphertextList`) and
/// pack the result in an output [`GLWE ciphertext`](`GlweCiphertext`).
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweTracePackingKeyswitchKey creation
/// let lwe_dimension = LweDimension(742);
/// let lwe_count = LweCiphertextCount(20);
/// let polynomial_size = PolynomialSize(2048);
/// let glwe_dimension = GlweDimension(1);
/// //let lwe_modular_std_dev = StandardDev(0.00000000000000000000001);
/// let ciphertext_modulus = CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap();
/// let delta = (1 << 60) - (1 << 28);
///
/// let mut seeder = new_seeder();
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
/// let lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
///
/// let mut glwe_secret_key = GlweSecretKey::new_empty_key(0u64, glwe_dimension, polynomial_size);
///
/// generate_tpksk_output_glwe_secret_key(&lwe_secret_key, &mut glwe_secret_key, ciphertext_modulus);
///
/// let decomp_base_log = DecompositionBaseLog(12);
/// let decomp_level_count = DecompositionLevelCount(4);
/// let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
///
/// let mut lwe_tpksk = LweTracePackingKeyswitchKey::new(
///     0u64,
///     decomp_base_log,
///     decomp_level_count,
///     lwe_dimension.to_lwe_size(),
///     glwe_dimension.to_glwe_size(),
///     polynomial_size,
///     ciphertext_modulus,
/// );
///
/// generate_lwe_trace_packing_keyswitch_key(
///     &glwe_secret_key,
///     &mut lwe_tpksk,
///     glwe_modular_std_dev,
///     &mut encryption_generator,
/// );
///
/// let mut lwe_ctxt_list = LweCiphertextList::new(
///     0u64,
///     lwe_dimension.to_lwe_size(),
///     lwe_count,
///     ciphertext_modulus,
/// );
///
/// let msg = 1u64;
/// let plaintext_list = PlaintextList::new(msg * delta, PlaintextCount(lwe_count.0));
///
/// encrypt_lwe_ciphertext_list(
///     &lwe_secret_key,
///     &mut lwe_ctxt_list,
///     &plaintext_list,
///     glwe_modular_std_dev,
///     &mut encryption_generator,
/// );
///
/// let mut output_glwe_ciphertext = GlweCiphertext::new(
///     0u64,
///     glwe_dimension.to_glwe_size(),
///     polynomial_size,
///     ciphertext_modulus,
/// );
///
/// let mut indices = vec![0_usize; lwe_count.0];
/// for (index, item) in indices.iter_mut().enumerate() {
///     *item = index;
/// }
///
/// trace_packing_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext(
///     &lwe_tpksk,
///     &mut output_glwe_ciphertext,
///     &lwe_ctxt_list,
///     indices,
/// );
///
/// let mut output_plaintext_list = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
///
/// decrypt_glwe_ciphertext(
///     &glwe_secret_key,
///     &output_glwe_ciphertext,
///     &mut output_plaintext_list,
/// );
///
/// // Round and remove encoding
/// // First create a decomposer working on the high 4 bits corresponding to our encoding.
/// let decomposer = SignedDecomposerNonNative::new(
///     DecompositionBaseLog(4),
///     DecompositionLevelCount(1),
///     ciphertext_modulus,
/// );
///
/// output_plaintext_list
///     .iter_mut()
///     .for_each(|elt| *elt.0 = decomposer.closest_representable(*elt.0));
///
/// // Get the raw vector
/// let mut cleartext_list = output_plaintext_list.into_container();
/// // Remove the encoding
/// cleartext_list
///     .iter_mut()
///     .for_each(|elt| *elt = (*elt + (delta/2)) / delta);
/// // Get the list immutably
/// let cleartext_list = cleartext_list;
///
/// // Check we recovered the original message for each plaintext we encrypted
/// for (index, elt) in cleartext_list.iter().enumerate() {
///     if index < lwe_count.0 {
///         assert_eq!(*elt, msg);
///     } else {
///         assert_eq!(*elt, 0);
///     }
/// }
/// ```
pub fn trace_packing_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext<
    Scalar,
    KeyCont,
    InputCont,
    OutputCont,
>(
    lwe_tpksk: &LweTracePackingKeyswitchKey<KeyCont>,
    output_glwe_ciphertext: &mut GlweCiphertext<OutputCont>,
    input_lwe_ciphertext_list: &LweCiphertextList<InputCont>,
    indices: Vec<usize>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(
        input_lwe_ciphertext_list.lwe_ciphertext_count().0
            <= output_glwe_ciphertext.polynomial_size().0
    );
    assert_eq!(
        input_lwe_ciphertext_list.lwe_ciphertext_count().0,
        indices.len()
    );
    assert_eq!(
        input_lwe_ciphertext_list.lwe_size(),
        lwe_tpksk.input_lwe_size()
    );
    assert!(indices
        .iter()
        .all(|&x| x < output_glwe_ciphertext.polynomial_size().0));
    assert_eq!(
        output_glwe_ciphertext.polynomial_size(),
        lwe_tpksk.polynomial_size()
    );
    assert_eq!(
        output_glwe_ciphertext.glwe_size(),
        lwe_tpksk.output_glwe_size()
    );
    assert_eq!(
        input_lwe_ciphertext_list.ciphertext_modulus(),
        lwe_tpksk.ciphertext_modulus()
    );
    assert_eq!(
        output_glwe_ciphertext.ciphertext_modulus(),
        lwe_tpksk.ciphertext_modulus()
    );
    // Check the ciphertext modulus is odd
    assert_eq!(Scalar::cast_from(input_lwe_ciphertext_list.ciphertext_modulus().get_custom_modulus
    ()) %
                   Scalar::TWO, Scalar::ONE);

    // We reset the output
    output_glwe_ciphertext.as_mut().fill(Scalar::ZERO);

    let poly_size = output_glwe_ciphertext.polynomial_size();
    let glwe_count = GlweCiphertextCount(poly_size.0);
    let ciphertext_modulus = output_glwe_ciphertext.ciphertext_modulus();

    let mut glwe_list = GlweCiphertextList::new(
        Scalar::ZERO,
        output_glwe_ciphertext.glwe_size(),
        poly_size,
        glwe_count,
        ciphertext_modulus,
    );

    // Construct the initial Glwe Ciphertexts
    for (index1, mut glwe_ct) in glwe_list.iter_mut().enumerate() {
        for (index2, index) in indices.iter().enumerate() {
            if index1 == *index {
                let lwe_ct = input_lwe_ciphertext_list.get(index2);
                let lwe_body = lwe_ct.as_ref().last().unwrap();
                let lwe_mask = lwe_ct.get_mask();
                for (index3, mut ring_element) in glwe_ct
                    .get_mut_mask()
                    .as_mut_polynomial_list()
                    .iter_mut()
                    .enumerate()
                {
                    for (index4, coef) in ring_element.iter_mut().enumerate() {
                        if index3 * poly_size.0 + index4 < lwe_mask.lwe_dimension().0 {
                            *coef =
                                coef.wrapping_add_custom_mod(lwe_mask.as_ref()[index3 * poly_size
                                    .0 + index4], ciphertext_modulus.get_custom_modulus().cast_into());
                        }
                    }
                }
                let mut poly_to_add = Polynomial::new(Scalar::ZERO, poly_size);
                poly_to_add[0] = poly_to_add[0].wrapping_add_custom_mod(*lwe_body, ciphertext_modulus.get_custom_modulus().cast_into());
                polynomial_wrapping_add_assign_custom_mod(
                    &mut glwe_ct.get_mut_body().as_mut_polynomial(),
                    &poly_to_add,
                    ciphertext_modulus.get_custom_modulus().cast_into(),
                );
            }
        }
    }

    for l in 0..poly_size.log2().0 {
        for i in 0..(poly_size.0 / 2_usize.pow(l as u32 + 1)) {
            let ct_0 = glwe_list.get(i);
            let glwe_size = ct_0.glwe_size();
            let j = (poly_size.0 / 2_usize.pow(l as u32 + 1)) + i;
            let ct_1 = glwe_list.get(j);
            if ct_0.as_ref().iter().any(|&x| x != Scalar::ZERO)
                || ct_1.as_ref().iter().any(|&x| x != Scalar::ZERO)
            {
                // Rotate ct_1 by N/2^(l+1)
                for mut pol in glwe_list.get_mut(j).as_mut_polynomial_list().iter_mut() {
                    polynomial_wrapping_monic_monomial_mul_assign_custom_mod(
                        &mut pol,
                        MonomialDegree(poly_size.0 / 2_usize.pow(l as u32 + 1)),
                        ciphertext_modulus.get_custom_modulus().cast_into(),
                    );
                }

                let mut ct_plus =
                    GlweCiphertext::new(Scalar::ZERO, glwe_size, poly_size, ciphertext_modulus);
                let mut ct_minus =
                    GlweCiphertext::new(Scalar::ZERO, glwe_size, poly_size, ciphertext_modulus);

                for ((mut pol_plus, pol_0), pol_1) in ct_plus
                    .as_mut_polynomial_list()
                    .iter_mut()
                    .zip(glwe_list.get(i).as_polynomial_list().iter())
                    .zip(glwe_list.get(j).as_polynomial_list().iter())
                {
                    // Dont need custom mod in first case
                    polynomial_wrapping_add_assign(&mut pol_plus, &pol_0);
                    polynomial_wrapping_add_assign_custom_mod(&mut pol_plus, &pol_1, ciphertext_modulus.get_custom_modulus().cast_into());
                }

                for ((mut pol_minus, pol_0), pol_1) in ct_minus
                    .as_mut_polynomial_list()
                    .iter_mut()
                    .zip(glwe_list.get(i).as_polynomial_list().iter())
                    .zip(glwe_list.get(j).as_polynomial_list().iter())
                {
                    // Dont need custom mod in first case
                    polynomial_wrapping_add_assign(&mut pol_minus, &pol_0);
                    polynomial_wrapping_sub_assign_custom_mod(&mut pol_minus, &pol_1,
                                                         ciphertext_modulus.get_custom_modulus().cast_into());
                }

                // Scale both ct_plus and ct_minus by 2^-1 mod q = (q+1) / 2 for odd q

                let scalar = (Scalar::cast_from(ciphertext_modulus.get_custom_modulus()) +
                    Scalar::ONE) /
                    Scalar::TWO;
                for mut pol in ct_plus.as_mut_polynomial_list().iter_mut() {
                    polynomial_wrapping_scalar_mul_assign_custom_mod(&mut pol, scalar,
                                                                     ciphertext_modulus.get_custom_modulus().cast_into());
                }
                for mut pol in ct_minus.as_mut_polynomial_list().iter_mut() {
                    polynomial_wrapping_scalar_mul_assign_custom_mod(&mut pol, scalar, ciphertext_modulus.get_custom_modulus().cast_into());
                }

                // Apply the automorphism sending X to X^(2^(l+1) + 1) to ct_minus
                for mut pol in ct_minus.as_mut_polynomial_list().iter_mut() {
                    apply_automorphism_assign_custom_mod(&mut pol, 2_usize.pow(l as u32 + 1) + 1,
                                                         ciphertext_modulus.get_custom_modulus().cast_into())
                }

                let mut ks_out = GlweCiphertext::new(
                    Scalar::ZERO,
                    ct_minus.glwe_size(),
                    poly_size,
                    ciphertext_modulus,
                );

                let glwe_ksk = GlweKeyswitchKey::from_container(
                    lwe_tpksk.get(l).into_container(),
                    lwe_tpksk.decomposition_base_log(),
                    lwe_tpksk.decomposition_level_count(),
                    lwe_tpksk.output_glwe_size(),
                    lwe_tpksk.polynomial_size(),
                    lwe_tpksk.ciphertext_modulus(),
                );

                // Perform a Glwe keyswitch on ct_minus
                keyswitch_glwe_ciphertext(&glwe_ksk, &mut ct_minus, &mut ks_out);

                // Set ct_0 to zero
                glwe_list.get_mut(i).as_mut().fill(Scalar::ZERO);

                // Add the result to ct_plus and add this to ct_0
                for ((mut pol_plus, pol_ks), mut pol_0) in ct_plus
                    .as_mut_polynomial_list()
                    .iter_mut()
                    .zip(ks_out.as_polynomial_list().iter())
                    .zip(glwe_list.get_mut(i).as_mut_polynomial_list().iter_mut())
                {
                    polynomial_wrapping_add_assign_custom_mod(&mut pol_plus, &pol_ks, ciphertext_modulus.get_custom_modulus().cast_into());
                    // Dont need custom mod
                    polynomial_wrapping_add_assign(&mut pol_0, &pol_plus);
                }
            }
        }
    }
    let res = glwe_list.get(0);
    output_glwe_ciphertext.as_mut().fill(Scalar::ZERO);
    for (mut pol_out, pol_res) in output_glwe_ciphertext
        .as_mut_polynomial_list()
        .iter_mut()
        .zip(res.as_polynomial_list().iter())
    {
        // Dont need custom mod here
        polynomial_wrapping_add_assign(&mut pol_out, &pol_res);
    }
}
