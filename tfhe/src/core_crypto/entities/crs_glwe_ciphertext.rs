//! Module containing the definition of the CRSGlweCiphertext.

use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// A convenience structure to easily manipulate the body of a [`CRSGlweCiphertext`].
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct CRSGlweBody<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    polynomial_size: PolynomialSize,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CRSGlweBody<C> {
    /// Create a [`CRSGlweBody`] from an existing container.
    ///
    /// # Note
    ///
    /// This docstring exhibits [`CRSGlweBody`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for CRSGlweBody creation
    /// let crs_glwe_codimension =CRSGlweCodimension(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// let crs_glwe_body = CRSGlweBody::from_container(
    ///     vec![0u64; crs_glwe_codimension.0 * polynomial_size.0],
    ///     polynomial_size,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(crs_glwe_body.crs_glwe_codimension(), crs_glwe_codimension);
    /// assert_eq!(crs_glwe_body.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        polynomial_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len() % polynomial_size.0 == 0,
            "The provided container length is not valid. \
        It needs to be dividable by polynomial_size. \
        Got container length: {} and polynomial_size: {polynomial_size:?}.",
            container.container_len()
        );
        CRSGlweBody {
            data: container,
            polynomial_size,
            ciphertext_modulus,
        }
    }

    /// Return the [`CRSGlweCodimension`] of the [`CRSGlweBody`].
    ///
    /// See [`CRSGlweBody::from_container`] for usage.
    pub fn crs_glwe_codimension(&self) -> CRSGlweCodimension {
        CRSGlweCodimension(self.data.container_len() / self.polynomial_size.0)
    }

    /// Return the [`PolynomialSize`] of the [`CRSGlweBody`].
    ///
    /// See [`CRSGlweBody::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    /// Return the [`CiphertextModulus`] of the [`CRSGlweBody`].
    ///
    /// See [`CRSGlweBody::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    /// Interpret the [`CRSGlweBody`] as a [`PolynomialList`].
    pub fn as_polynomial_list(&self) -> PolynomialListView<'_, C::Element> {
        PolynomialListView::from_container(self.as_ref(), self.polynomial_size)
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> CRSGlweBody<C> {
    /// Mutable variant of [`CRSGlweBody::as_polynomial_list`].
    pub fn as_mut_polynomial_list(&mut self) -> PolynomialListMutView<'_, C::Element> {
        let polynomial_size = self.polynomial_size;
        PolynomialListMutView::from_container(self.as_mut(), polynomial_size)
    }
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for CRSGlweBody<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for CRSGlweBody<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}
/// Return the number of elements in a [`CRSGlweBody`] given a [`CRSGlweCodimension`] and
/// [`PolynomialSize`].
pub fn crs_glwe_ciphertext_body_size(
    crs_glwe_codimension: CRSGlweCodimension,
    polynomial_size: PolynomialSize,
) -> usize {
    crs_glwe_codimension.0 * polynomial_size.0
}

/// A convenience structure to easily manipulate the mask of a [`CRSGlweCiphertext`].
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct CRSGlweMask<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    polynomial_size: PolynomialSize,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CRSGlweMask<C> {
    /// Create a [`CRSGlweMask`] from an existing container.
    ///
    /// # Note
    ///
    /// This docstring exhibits [`CRSGlweMask`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for CRSGlweMask creation
    /// let crs_glwe_dimension = CRSGlweDimension(1);
    /// let polynomial_size = PolynomialSize(1024);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// let crs_glwe_mask = CRSGlweMask::from_container(
    ///     vec![0u64; crs_glwe_dimension.0 * polynomial_size.0],
    ///     polynomial_size,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(crs_glwe_mask.crs_glwe_dimension(), crs_glwe_dimension);
    /// assert_eq!(crs_glwe_mask.polynomial_size(), polynomial_size);
    /// assert_eq!(crs_glwe_mask.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        polynomial_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len() % polynomial_size.0 == 0,
            "The provided container length is not valid. \
        It needs to be dividable by polynomial_size. \
        Got container length: {} and polynomial_size: {polynomial_size:?}.",
            container.container_len()
        );
        CRSGlweMask {
            data: container,
            polynomial_size,
            ciphertext_modulus,
        }
    }

    /// Return the [`CRSGlweDimension`] of the [`CRSGlweMask`].
    ///
    /// See [`CRSGlweMask::from_container`] for usage.
    pub fn crs_glwe_dimension(&self) -> CRSGlweDimension {
        CRSGlweDimension(self.data.container_len() / self.polynomial_size.0)
    }

    /// Return the [`PolynomialSize`] of the [`CRSGlweMask`].
    ///
    /// See [`CRSGlweMask::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    /// Return the [`CiphertextModulus`] of the [`CRSGlweMask`].
    ///
    /// See [`CRSGlweMask::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    /// Interpret the [`CRSGlweMask`] as a [`PolynomialList`].
    pub fn as_polynomial_list(&self) -> PolynomialListView<'_, C::Element> {
        PolynomialListView::from_container(self.as_ref(), self.polynomial_size)
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> CRSGlweMask<C> {
    /// Mutable variant of [`CRSGlweMask::as_polynomial_list`].
    pub fn as_mut_polynomial_list(&mut self) -> PolynomialListMutView<'_, C::Element> {
        let polynomial_size = self.polynomial_size;
        PolynomialListMutView::from_container(self.as_mut(), polynomial_size)
    }
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for CRSGlweMask<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for CRSGlweMask<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}


/// Return the number of elements in a [`CRSGlweCiphertext`] given a [`CRSGlweSize`] and
/// [`PolynomialSize`].
pub fn crs_glwe_ciphertext_size(crs_glwe_size: CRSGlweSize, polynomial_size: PolynomialSize) -> usize {
    crs_glwe_size.0 * polynomial_size.0
}

/// Return the number of elements in a [`CRSGlweMask`] given a [`CRSGlweDimension`] and
/// [`PolynomialSize`].
pub fn crs_glwe_ciphertext_mask_size(
    crs_glwe_dimension: CRSGlweDimension,
    polynomial_size: PolynomialSize,
) -> usize {
    crs_glwe_dimension.0 * polynomial_size.0
}

/// A [`CRSGLWE ciphertext`](`CRSGlweCiphertext`).
///
/// **Remark:** GLWE ciphertexts generalize LWE ciphertexts by definition, however in this library,
/// GLWE ciphertext entities do not generalize LWE ciphertexts, i.e., polynomial size cannot be 1.
///
/// # Formal Definition
///
/// ## GLWE Ciphertext
///
/// A GLWE ciphertext is an encryption of a polynomial plaintext.
/// It is secure under the hardness assumption called General Learning With Errors (GLWE). It is a
/// generalization of both [`LWE ciphertexts`](`crate::core_crypto::entities::LweCiphertext`) and
/// RLWE ciphertexts. GLWE requires a cyclotomic ring. We use the notation $\mathcal{R}\_q$ for the
/// following cyclotomic ring: $\mathbb{Z}\_q\[X\]/\left\langle X^N + 1\right\rangle$ where
/// $N\in\mathbb{N}$ is a power of two.
///
/// We call $q$ the ciphertext modulus and $N$ the ring dimension.
///
/// We indicate a GLWE ciphertext of a plaintext $\mathsf{PT} \in\mathcal{R}\_q^{k+1}$ as the
/// following couple: $$\mathsf{CT} = \left( \vec{A}, B\right) = \left( A\_0, \ldots, A\_{k-1},
/// B\right) \in \mathsf{GLWE}\_{\vec{S}} \left( \mathsf{PT} \right) \subseteq
/// \mathcal{R}\_q^{k+1}$$
///
/// ## Generalisation of LWE and RLWE
///
/// When we set $k=1$ a GLWE ciphertext becomes an RLWE ciphertext.
/// When we set $N=1$ a GLWE ciphertext becomes an LWE ciphertext with $n=k$.
///
/// ## GLWE Encryption
/// ###### inputs:
/// - $\mathsf{PT}\in\mathcal{R}\_q$: a plaintext
/// - $\vec{S} \in\mathcal{R}\_q^k$: a secret key
/// - $\mathcal{D\_{\sigma^2,\mu}}$: a normal distribution of variance $\sigma^2$ and mean $\mu$
///
/// ###### outputs:
/// - $\mathsf{CT} = \left( \vec{A} , B \right) \in \mathsf{GLWE}\_{\vec{S}}( \mathsf{PT} )\subseteq
///   \mathcal{R}\_q^{k+1}$: an GLWE ciphertext
///
/// ###### algorithm:
/// 1. uniformly sample each coefficient of the polynomial vector $\vec{A}\in\mathcal{R}^k\_q$
/// 2. sample each integer error coefficient of an error polynomial $E\in\mathcal{R}\_q$ from
/// $\mathcal{D\_{\sigma^2,\mu}}$ 3. compute $B = \left\langle \vec{A} , \vec{S} \right\rangle +
/// \mathsf{PT} + E \in\mathcal{R}\_q$ 4. output $\left( \vec{A} , B \right)$
///
/// ## GLWE Decryption
/// ###### inputs:
/// - $\mathsf{CT} = \left( \vec{A} , B \right) \in \mathsf{GLWE}\_{\vec{S}}( \mathsf{PT} )\subseteq
///   \mathcal{R}\_q^{k+1}$: an GLWE ciphertext
/// - $\vec{S} \in\mathcal{R}\_q^k$: a secret key
///
/// ###### outputs:
/// - $\mathsf{PT}\in\mathcal{R}\_q$: a plaintext
///
/// ###### algorithm:
///
/// 1. compute $\mathsf{PT} = B - \left\langle \vec{A} , \vec{S} \right\rangle \in\mathcal{R}\_q$
/// 2. output $\mathsf{PT}$
///
/// **Remark:** Observe that the decryption is followed by a decoding phase that will contain a
/// rounding.
#[derive(Clone, Debug, PartialEq)]
pub struct CRSGlweCiphertext<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    codim: usize,
    polynomial_size: PolynomialSize,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for CRSGlweCiphertext<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for CRSGlweCiphertext<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CRSGlweCiphertext<C> {
    /// Create a [`CRSGlweCiphertext`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to encrypt data
    /// you need to use [`crate::core_crypto::algorithms::encrypt_crs_glwe_ciphertext`] using this
    /// ciphertext as output.
    ///
    /// This docstring exhibits [`CRSGlweCiphertext`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for CRSGlweCiphertext creation
    /// let crs_glwe_size = CRSGlweSize(4,2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new CRSGlweCiphertext
    /// let mut crs_glwe = CRSGlweCiphertext::new(0u64, crs_glwe_size, polynomial_size, ciphertext_modulus);
    ///
    /// assert_eq!(crs_glwe.crs_glwe_size(), crs_glwe_size);
    /// assert_eq!(crs_glwe.polynomial_size(), polynomial_size);
    /// assert_eq!(crs_glwe.ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(crs_glwe.get_body().polynomial_size(), polynomial_size);
    /// assert_eq!(crs_glwe.get_mut_body().polynomial_size(), polynomial_size);
    /// assert_eq!(crs_glwe.get_body().ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(crs_glwe.get_mut_body().ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(
    ///     crs_glwe.get_mask().crs_glwe_dimension(),
    ///     crs_glwe_size.to_crs_glwe_dimension()
    /// );
    /// assert_eq!(
    ///     crs_glwe.get_mut_mask().crs_glwe_dimension(),
    ///     crs_glwe_size.to_crs_glwe_dimension()
    /// );
    /// assert_eq!(crs_glwe.get_mask().polynomial_size(), polynomial_size);
    /// assert_eq!(crs_glwe.get_mut_mask().polynomial_size(), polynomial_size);
    /// assert_eq!(crs_glwe.get_mask().ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(crs_glwe.get_mut_mask().ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = crs_glwe.into_container();
    ///
    /// // Recreate a ciphertext using from_container
    /// let mut crs_glwe =
    ///     CRSGlweCiphertext::from_container(underlying_container, polynomial_size, ciphertext_modulus,crs_glwe_size.1);
    ///
    /// assert_eq!(crs_glwe.crs_glwe_size(), crs_glwe_size);
    /// assert_eq!(crs_glwe.polynomial_size(), polynomial_size);
    /// assert_eq!(crs_glwe.ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(crs_glwe.get_body().polynomial_size(), polynomial_size);
    /// assert_eq!(crs_glwe.get_mut_body().polynomial_size(), polynomial_size);
    /// assert_eq!(crs_glwe.get_body().ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(crs_glwe.get_mut_body().ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(
    ///     crs_glwe.get_mask().crs_glwe_dimension(),
    ///     crs_glwe_size.to_crs_glwe_dimension()
    /// );
    /// assert_eq!(
    ///     crs_glwe.get_mut_mask().crs_glwe_dimension(),
    ///     crs_glwe_size.to_crs_glwe_dimension()
    /// );
    /// assert_eq!(crs_glwe.get_mask().polynomial_size(), polynomial_size);
    /// assert_eq!(crs_glwe.get_mut_mask().polynomial_size(), polynomial_size);
    /// assert_eq!(crs_glwe.get_mask().ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(crs_glwe.get_mut_mask().ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        polynomial_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<C::Element>,
        cod: usize,
    ) -> CRSGlweCiphertext<C> {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create a CRSGlweCiphertext"
        );
        assert!(
            container.container_len() % polynomial_size.0 == 0,
            "The provided container length is not valid. \
        It needs to be dividable by polynomial_size. \
        Got container length: {} and polynomial_size: {polynomial_size:?}.",
            container.container_len()
        );
        CRSGlweCiphertext {
            data: container,
            codim:cod,
            polynomial_size,
            ciphertext_modulus,
            
        }
    }

    /// Return the [`CRSGlweSize`] of the [`CRSGlweCiphertext`].
    ///
    /// See [`CRSGlweCiphertext::from_container`] for usage.
    pub fn crs_glwe_size(&self) -> CRSGlweSize {
        CRSGlweSize(self.as_ref().container_len() / self.polynomial_size.0, self.codim )
    }

    /// Return the [`PolynomialSize`] of the [`CRSGlweCiphertext`].
    ///
    /// See [`CRSGlweCiphertext::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    /// Return the [`CiphertextModulus`] of the [`CRSGlweCiphertext`].
    ///
    /// See [`CRSGlweCiphertext::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    /// Return immutable views to the [`CRSGlweMask`] and [`CRSGlweBody`] of a [`CRSGlweCiphertext`].
    pub fn get_mask_and_body(&self) -> (CRSGlweMask<&[Scalar]>, CRSGlweBody<&[Scalar]>) {
        let (mask, body) = self.data.as_ref().split_at(crs_glwe_ciphertext_mask_size(
            self.crs_glwe_size().to_crs_glwe_dimension(),
            self.polynomial_size,
        ));

        (
            CRSGlweMask::from_container(mask,self.polynomial_size, self.ciphertext_modulus),
            CRSGlweBody::from_container(body,self.polynomial_size, self.ciphertext_modulus),
        )
    }

    /// Return an immutable view to the [`CRSGlweBody`] of a [`GlweCiphertext`].
    ///
    /// See [`CRSGlweCiphertext::from_container`] for usage.
    pub fn get_body(&self) -> CRSGlweBody<&[Scalar]> {
        let body = &self.data.as_ref()[crs_glwe_ciphertext_mask_size(
            self.crs_glwe_size().to_crs_glwe_dimension(),
            self.polynomial_size,
        )..];

        CRSGlweBody::from_container(body, self.polynomial_size,self.ciphertext_modulus)
    }

    /// Return an immutable view to the [`CRSGlweMask`] of a [`CRSGlweCiphertext`].
    ///
    /// See [`CRSGlweCiphertext::from_container`] for usage.
    pub fn get_mask(&self) -> CRSGlweMask<&[Scalar]> {
        CRSGlweMask::from_container(
            &self.as_ref()[0..crs_glwe_ciphertext_mask_size(
                self.crs_glwe_size().to_crs_glwe_dimension(),
                self.polynomial_size,
            )],
            self.polynomial_size,
            self.ciphertext_modulus,
        )
    }

    /// Interpret the [`CRSGlweCiphertext`] as a [`PolynomialList`].
    pub fn as_polynomial_list(&self) -> PolynomialList<&'_ [Scalar]> {
        PolynomialList::from_container(self.as_ref(), self.polynomial_size)
    }

    /// Return a view of the [`CRSGlweCiphertext`]. This is useful if an algorithm takes a view by
    /// value.
    pub fn as_view(&self) -> CRSGlweCiphertext<&'_ [Scalar]> {
        CRSGlweCiphertext {
            data: self.data.as_ref(),
            codim: self.codim,
            polynomial_size: self.polynomial_size,
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`CRSGlweCiphertext::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> CRSGlweCiphertext<C> {
    /// Mutable variant of [`CRSGlweCiphertext::get_mask_and_body`].
    pub fn get_mut_mask_and_body(&mut self) -> (CRSGlweMask<&mut [Scalar]>, CRSGlweBody<&mut [Scalar]>) {
        let crs_glwe_dimension = self.crs_glwe_size().to_crs_glwe_dimension();
        let polynomial_size = self.polynomial_size();
        let ciphertext_modulus = self.ciphertext_modulus();

        let (mask, body) = self
            .data
            .as_mut()
            .split_at_mut(crs_glwe_ciphertext_mask_size(crs_glwe_dimension, polynomial_size));

        (
            CRSGlweMask::from_container(mask, polynomial_size, ciphertext_modulus),
            CRSGlweBody::from_container(body, polynomial_size, ciphertext_modulus),
        )
    }

    /// Mutable variant of [`CRSGlweCiphertext::get_body`].
    ///
    /// See [`CRSGlweCiphertext::from_container`] for usage.
    pub fn get_mut_body(&mut self) -> CRSGlweBody<&mut [Scalar]> {
        let crs_glwe_dimension = self.crs_glwe_size().to_crs_glwe_dimension();
        let polynomial_size = self.polynomial_size();
        let ciphertext_modulus = self.ciphertext_modulus();

        let body =
            &mut self.data.as_mut()[crs_glwe_ciphertext_mask_size(crs_glwe_dimension, polynomial_size)..];

        CRSGlweBody::from_container(body, polynomial_size,ciphertext_modulus)
    }

    /// Mutable variant of [`CRSGlweCiphertext::get_mask`].
    ///
    /// See [`CRSGlweCiphertext::from_container`] for usage.
    pub fn get_mut_mask(&mut self) -> CRSGlweMask<&mut [Scalar]> {
        let polynomial_size = self.polynomial_size();
        let crs_glwe_dimension = self.crs_glwe_size().to_crs_glwe_dimension();
        let ciphertext_modulus = self.ciphertext_modulus();

        CRSGlweMask::from_container(
            &mut self.as_mut()[0..crs_glwe_ciphertext_mask_size(crs_glwe_dimension, polynomial_size)],
            polynomial_size,
            ciphertext_modulus,
        )
    }

    /// Mutable variant of [`CRSGlweCiphertext::as_polynomial_list`].
    pub fn as_mut_polynomial_list(&mut self) -> PolynomialList<&'_ mut [Scalar]> {
        let polynomial_size = self.polynomial_size;
        PolynomialList::from_container(self.as_mut(), polynomial_size)
    }

    /// Mutable variant of [`CRSGlweCiphertext::as_view`].
    pub fn as_mut_view(&mut self) -> CRSGlweCiphertext<&'_ mut [Scalar]> {
        CRSGlweCiphertext {
            data: self.data.as_mut(),
            codim: self.codim,
            polynomial_size: self.polynomial_size,
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }
}

/// A [`CRSGlweCiphertext`] owning the memory for its own storage.
pub type CRSGlweCiphertextOwned<Scalar> = CRSGlweCiphertext<Vec<Scalar>>;
/// A [`CRSGlweCiphertext`] immutably borrowing memory for its own storage.
pub type CRSGlweCiphertextView<'data, Scalar> = CRSGlweCiphertext<&'data [Scalar]>;
/// A [`CRSGlweCiphertext`] mutably borrowing memory for its own storage.
pub type CRSGlweCiphertextMutView<'data, Scalar> = CRSGlweCiphertext<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> CRSGlweCiphertextOwned<Scalar> {
    /// Allocate memory and create a new owned [`CRSGlweCiphertext`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to encrypt data you need to use
    /// [`crate::core_crypto::algorithms::encrypt_crs_glwe_ciphertext`] using this ciphertext as
    /// output.
    ///
    ///
    /// See [`CRSGlweCiphertext::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        crs_glwe_size: CRSGlweSize,
        polynomial_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<Scalar>,
        
    ) -> CRSGlweCiphertextOwned<Scalar> {
        CRSGlweCiphertextOwned::from_container(
            vec![fill_with; crs_glwe_ciphertext_size(crs_glwe_size, polynomial_size)],
            polynomial_size,
            ciphertext_modulus,
            crs_glwe_size.1,
        )
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create [`CRSGlweCiphertext`] entities.
#[derive(Clone, Copy)]
pub struct CRSGlweCiphertextCreationMetadata<Scalar: UnsignedInteger>(
    pub PolynomialSize,
    pub CiphertextModulus<Scalar>,
    pub usize,
);

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C> for CRSGlweCiphertext<C> {
    type Metadata = CRSGlweCiphertextCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> CRSGlweCiphertext<C> {
        let CRSGlweCiphertextCreationMetadata(polynomial_size, ciphertext_modulus,codim) = meta;
        CRSGlweCiphertext::from_container(from, polynomial_size, ciphertext_modulus,codim)
    }
}
