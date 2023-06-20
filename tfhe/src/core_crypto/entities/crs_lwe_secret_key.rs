//! Module containing the definition of the CRSLweSecretKey.

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::generators::SecretRandomGenerator;
use crate::core_crypto::commons::math::random::{RandomGenerable, UniformBinary};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;

/// A [`CRSLWE secret key`](`CRSLweSecretKey`).
///
/// # Formal Definition
///
/// ## CRS LWE Secret Key
///
/// We consider a secret key:
/// $$\vec{s} \in \mathbb{Z}^n$$
/// This vector contains $ n=k*d $ integers that have been sampled for some distribution which is either
/// uniformly binary, uniformly ternary, gaussian or even uniform.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CRSLweSecretKey<C: Container> {
    data: C,
    codimension: usize, 
}

impl<T, C: Container<Element = T>> AsRef<[T]> for CRSLweSecretKey<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for CRSLweSecretKey<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar, C: Container<Element = Scalar>> CRSLweSecretKey<C> {
    /// Create a [`CRSLweSecretKey`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate a
    /// [`CRSLweSecretKey`] you need to call
    /// [`crate::core_crypto::algorithms::generate_binary_crs_lwe_secret_key`] (or other generation
    /// functions working with different coefficient distributions) using this secret key as
    /// output.
    ///
    /// This docstring exhibits [`CRSLweSecretKey`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for CRSLweSecretKey creation
    /// let crs_lwe_dimension = CRSLweDimension(600);
    /// let crs_lwe_codimension = CRSLweCodimension(7);
    /// // Create a new CRSLweSecretKey
    /// let crs_lwe_secret_key = CRSLweSecretKey::new_empty_key(0u64, crs_lwe_dimension,crs_lwe_codimension);
    ///
    /// assert_eq!(crs_lwe_secret_key.crs_lwe_dimension(), crs_lwe_dimension);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = crs_lwe_secret_key.into_container();
    ///
    /// // Recreate a secret key using from_container
    /// let crs_lwe_secret_key = CRSLweSecretKey::from_container(underlying_container,crs_lwe_codimension.0);
    ///
    /// assert_eq!(crs_lwe_secret_key.crs_lwe_dimension(), crs_lwe_dimension);
    /// ```
    pub fn from_container(container: C, codim: usize) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create a CRSLweSecretKey"
        );
        CRSLweSecretKey { data: container, codimension: codim }
    }

    /// Return the [`CRSLweDimension`] of the [`CRSLweSecretKey`].
    ///
    /// See [`CRSLweSecretKey::from_container`] for usage.
    pub fn crs_lwe_dimension(&self) -> CRSLweDimension {
        let dim: i64= (self.data.container_len() as i64)/(self.codimension as i64);
        CRSLweDimension(dim as usize )
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`CRSLweSecretKey::from_container`] for usage.
    pub fn into_container(self ) -> C {
        self.data
    }
}

/// A [`CRSLweSecretKey`] owning the memory for its own storage.
pub type CRSLweSecretKeyOwned<Scalar> = CRSLweSecretKey<Vec<Scalar>>;

impl<Scalar> CRSLweSecretKeyOwned<Scalar>
where
    Scalar: Copy,
{
    /// Allocate memory and create a new empty owned [`CRSLweSecretKey`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate a [`CRSLweSecretKey`] you need to call
    /// [`generate_new_binary`](`Self::generate_new_binary`) or
    /// [`crate::core_crypto::algorithms::generate_binary_crs_lwe_secret_key`] (or other generation
    /// functions working with different coefficient distributions) using this secret key as
    /// output.
    ///
    /// See [`CRSLweSecretKey::from_container`] for usage.
    pub fn new_empty_key(
        fill_with: Scalar,
        crs_lwe_dimension: CRSLweDimension,
        crs_lwe_codimension: CRSLweCodimension,
    ) -> CRSLweSecretKeyOwned<Scalar> {
        CRSLweSecretKeyOwned::from_container(vec![fill_with; crs_lwe_dimension.0*crs_lwe_codimension.0], crs_lwe_codimension.0)
    }

    /// Allocate a new owned [`CRSLweSecretKey`] and fill it with binary coefficients.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for CRSLweSecretKey creation
    /// let crs_lwe_dimension = CRSLweDimension(742);
    /// let crs_lwe_codimension = CRSLweCodimension(7);
    /// // Create the PRNG
    /// let mut seeder = new_seeder();
    /// let seeder = seeder.as_mut();
    /// let mut secret_generator =
    ///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    ///
    /// let crs_lwe_secret_key: CRSLweSecretKeyOwned<u64> =
    ///     CRSLweSecretKey::generate_new_binary(crs_lwe_dimension,crs_lwe_codimension, &mut secret_generator);
    ///
    /// // Check all coefficients are not zero as we just generated a new key
    /// // Note probability of this assert failing is (1/2)^crs-lwe_dimension or ~4.3 * 10^-224 for a
    /// // CRSLWE dimension of 742.
    /// assert!(crs_lwe_secret_key.as_ref().iter().all(|&elt| elt == 0) == false);
    /// ```
    pub fn generate_new_binary<Gen>(
        crs_lwe_dimension: CRSLweDimension,
        crs_lwe_codimension: CRSLweCodimension,
        generator: &mut SecretRandomGenerator<Gen>,
    ) -> CRSLweSecretKeyOwned<Scalar>
    where
        Scalar: Numeric + RandomGenerable<UniformBinary>,
        Gen: ByteRandomGenerator,
    {
        let mut crs_lwe_sk = Self::new_empty_key(Scalar::ZERO, crs_lwe_dimension,crs_lwe_codimension);
        generate_binary_crs_lwe_secret_key(&mut crs_lwe_sk, generator);
        crs_lwe_sk
    }
}
