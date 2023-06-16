//! Module containing the definition of the CRSGlweSecretKey.

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::generators::SecretRandomGenerator;
use crate::core_crypto::commons::math::random::{RandomGenerable, UniformBinary};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// A [`CRSGLWE secret key`](`CRSGlweSecretKey`)
///
/// # Formal Definition
///
/// ## CRSGLWE Secret Key
///
/// We consider a secret key:
/// $$\vec{S} =\left( S\_0, \ldots, S\_{k*d-1}\right) \in \mathcal{R}^{k*d}$$
/// The $k*d$ polynomials composing $\vec{S}$ contain each $N$ integers coefficients that have been
/// sampled from some distribution which is either uniformly binary, uniformly ternary, gaussian or
/// even uniform.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CRSGlweSecretKey<C: Container> {
    data: C,
    polynomial_size: PolynomialSize,
    codimension:usize,
}

impl<T, C: Container<Element = T>> AsRef<[T]> for CRSGlweSecretKey<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for CRSGlweSecretKey<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar, C: Container<Element = Scalar>> CRSGlweSecretKey<C> {
    /// Create a [`CRSGlweSecretKey`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate a
    /// [`CRSGlweSecretKey`] you need to call
    /// [`crate::core_crypto::algorithms::generate_binary_crs_glwe_secret_key`] (or other generation
    /// functions working with different coefficient distributions) using this secret key as
    /// output.
    ///
    /// This docstring exhibits [`CRSGlweSecretKey`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for GlweSecretKey creation
    /// let crs_glwe_dimension = CRSGlweDimension(2);
    /// let crs_glwe_codimension = CRSGlweCodimension(2);
    /// let polynomial_size = PolynomialSize(1024);
    ///
    /// // Create a new CRSGlweSecretKey
    /// let crs_glwe_secret_key = CRSGlweSecretKey::new_empty_key(0u64, crs_glwe_dimension,crs_glwe_codimension, polynomial_size);
    ///
    /// assert_eq!(crs_glwe_secret_key.crs_glwe_dimension(), crs_glwe_dimension);
    /// assert_eq!(crs_glwe_secret_key.polynomial_size(), polynomial_size);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = crs_glwe_secret_key.into_container();
    ///
    /// // Recreate a secret key using from_container
    /// let crs_glwe_secret_key = CRSGlweSecretKey::from_container(underlying_container, polynomial_size,crs_glwe_codimension.0);
    ///
    /// assert_eq!(crs_glwe_secret_key.crs_glwe_dimension(), crs_glwe_dimension);
    /// assert_eq!(crs_glwe_secret_key.polynomial_size(), polynomial_size);
    /// ```
    pub fn from_container(container: C, polynomial_size: PolynomialSize, codim:usize) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create a CRSGlweSecretKey"
        );
        assert!(
            container.container_len() % polynomial_size.0 == 0,
            "The provided container length is not valid. \
        It needs to be dividable by polynomial_size. \
        Got container length: {} and polynomial_size: {polynomial_size:?}",
            container.container_len()
        );
        CRSGlweSecretKey {
            data: container,
            polynomial_size,
            codimension:codim,
        }
    }

    /// Return the [`CRSGlweDimension`] of the [`CRSGlweSecretKey`].
    ///
    /// See [`CRSGlweSecretKey::from_container`] for usage.
    pub fn crs_glwe_dimension(&self) -> CRSGlweDimension {
        CRSGlweDimension(self.data.container_len() / self.polynomial_size.0 / self.codimension)
    }

    /// Return the [`PolynomialSize`] of the [`CRSGlweSecretKey`].
    ///
    /// See [`CRSGlweSecretKey::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    /// Consume the [`CRSGlweSecretKey`] and return it interpreted as an [`CRSLweSecretKey`].
    pub fn into_crs_lwe_secret_key(self) -> CRSLweSecretKey<C> {
        CRSLweSecretKey::from_container(self.data, self.codimension)
    }

    /// Interpret the [`CRSGlweSecretKey`] as a [`PolynomialList`].
    pub fn as_polynomial_list(&self) -> PolynomialListView<'_, C::Element> {
        PolynomialListView::from_container(self.as_ref(), self.polynomial_size)
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`CRSGlweSecretKey::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }
}

/// A [`CRSGlweSecretKey`] owning the memory for its own storage.
pub type CRSGlweSecretKeyOwned<Scalar> = CRSGlweSecretKey<Vec<Scalar>>;

impl<Scalar> CRSGlweSecretKeyOwned<Scalar>
where
    Scalar: Copy,
{
    /// Allocate memory and create a new empty owned [`CRSGlweSecretKey`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate a [`GlweSecretKey`] you need to call
    /// [`generate_new_binary`](`Self::generate_new_binary`) or
    /// [`crate::core_crypto::algorithms::generate_binary_glwe_secret_key`] (or other generation
    /// functions working with different coefficient distributions) using this secret key as
    /// output.
    ///
    /// See [`GlweCiphertext::from_container`] for usage.
    pub fn new_empty_key(
        value: Scalar,
        crs_glwe_dimension: CRSGlweDimension,
        crs_glwe_codimension: CRSGlweCodimension,
        polynomial_size: PolynomialSize,
    ) -> CRSGlweSecretKeyOwned<Scalar> {
        CRSGlweSecretKeyOwned::from_container(
            vec![value; crs_glwe_dimension.0 * polynomial_size.0*crs_glwe_codimension.0],
            polynomial_size,crs_glwe_codimension.0
        )
    }

    /// Allocate a new owned [`CRSGlweSecretKey`] and fill it with binary coefficients.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for CRSGlweSecretKey creation
    /// let crs_glwe_size = CRSGlweSize(4,2);
    /// let polynomial_size = PolynomialSize(1024);
    ///
    /// // Create the PRNG
    /// let mut seeder = new_seeder();
    /// let seeder = seeder.as_mut();
    /// let mut secret_generator =
    ///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    ///
    /// let crs_glwe_secret_key: CRSGlweSecretKeyOwned<u64> = CRSGlweSecretKey::generate_new_binary(
    ///     crs_glwe_size.to_crs_glwe_dimension(),
    ///     crs_glwe_size.to_crs_glwe_codimension(),
    ///     polynomial_size,
    ///     &mut secret_generator,
    /// );
    ///
    /// // Check all coefficients are not zero as we just generated a new key
    /// // Note probability of this assert failing is (1/2)^polynomial_size or ~5.6 * 10^-309 for a
    /// // polynomial size of 1024.
    /// assert!(crs_glwe_secret_key.as_ref().iter().all(|&elt| elt == 0) == false);
    /// ```
    pub fn generate_new_binary<Gen>(
        crs_glwe_dimension: CRSGlweDimension,
        crs_glwe_codimension: CRSGlweCodimension,
        polynomial_size: PolynomialSize,
        generator: &mut SecretRandomGenerator<Gen>,
    ) -> CRSGlweSecretKeyOwned<Scalar>
    where
        Scalar: Numeric + RandomGenerable<UniformBinary>,
        Gen: ByteRandomGenerator,
    {
        let mut glwe_sk = Self::new_empty_key(Scalar::ZERO, crs_glwe_dimension,crs_glwe_codimension, polynomial_size);
        generate_binary_crs_glwe_secret_key(&mut glwe_sk, generator);
        glwe_sk
    }
}

