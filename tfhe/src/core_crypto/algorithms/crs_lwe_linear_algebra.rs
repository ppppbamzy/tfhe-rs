//! Module containing primitives pertaining to [`CRSLWE ciphertext`](`CRSLweCiphertext`) linear algebra,
//! like addition, multiplication, etc.

use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

pub fn crs_lwe_ciphertext_add_assign<Scalar, LhsCont, RhsCont>(
    lhs: &mut CRSLweCiphertext<LhsCont>,
    rhs: &CRSLweCiphertext<RhsCont>,
) where
    Scalar: UnsignedInteger,
    LhsCont: ContainerMut<Element = Scalar>,
    RhsCont: Container<Element = Scalar>,
{
    assert_eq!(
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus(),
        "Mismatched moduli between lhs ({:?}) and rhs ({:?}) CRSLweCiphertext",
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus()
    );

    slice_wrapping_add_assign(lhs.as_mut(), rhs.as_ref());
}

pub fn crs_lwe_ciphertext_add<Scalar, OutputCont, LhsCont, RhsCont>(
    output: &mut CRSLweCiphertext<OutputCont>,
    lhs: &CRSLweCiphertext<LhsCont>,
    rhs: &CRSLweCiphertext<RhsCont>,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    LhsCont: Container<Element = Scalar>,
    RhsCont: Container<Element = Scalar>,
{
    assert_eq!(
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus(),
        "Mismatched moduli between lhs ({:?}) and rhs ({:?}) CRSLweCiphertext",
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus()
    );

    assert_eq!(
        output.ciphertext_modulus(),
        rhs.ciphertext_modulus(),
        "Mismatched moduli between output ({:?}) and rhs ({:?}) CRSLweCiphertext",
        output.ciphertext_modulus(),
        rhs.ciphertext_modulus()
    );

    slice_wrapping_add(output.as_mut(), lhs.as_ref(), rhs.as_ref());
}
pub fn crs_lwe_ciphertext_plaintext_add_assign<Scalar, InCont>(
    lhs: &mut CRSLweCiphertext<InCont>,
    rhs: Plaintext<Scalar>,
) where
    Scalar: UnsignedInteger,
    InCont: ContainerMut<Element = Scalar>,
{
    let body = lhs.get_mut_body();
    let ciphertext_modulus = body.ciphertext_modulus();
    if ciphertext_modulus.is_native_modulus() {
        slice_wrapping_add_assign(body, rhs.0 );
        //*body.data = (*body.data).slice_wrapping_add(rhs.0);//to check
    } else {
        slice_wrapping_add_assign(body, rhs.0.slice_wrapping_mul(ciphertext_modulus.get_scaling_to_native_torus()) );
        //*body.data = (*body.data).slice_wrapping_add(
        //    rhs.0
        //        .slice_wrapping_mul(ciphertext_modulus.get_scaling_to_native_torus()),
        //);
    }
}