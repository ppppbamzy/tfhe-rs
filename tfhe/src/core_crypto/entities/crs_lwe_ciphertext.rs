//! Module containing the definition of the [`CRSLweCiphertext`].

use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
//use crate::core_crypto::entities::*;

/// A convenience structure to easily manipulate the body of a [`CRSLweCiphertext`].
/// 
/// 
/// 
#[derive(Clone, Debug)]
pub struct CRSLweBody<C: Container>
where
    C::Element: UnsignedInteger,
{
    pub data: C,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar> > CRSLweBody<C> {
    /// Create a [`CRSLweBody`] from an existing container.
    ///
    /// # Note
    ///
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for CRSLweMask creation
    /// let crs_lwe_codimension = CRSLweCodimension(5);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// let crs_lwe_body = CRSLweBody::from_container(vec![0u64; crs_lwe_codimension.0], ciphertext_modulus); //A regarder!!!!!!!!!!!!!!!!!!!!!
    ///
    /// assert_eq!(crs_lwe_body.crs_lwe_codimension(), crs_lwe_codimension);
    /// assert_eq!(crs_lwe_body.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(container: C, ciphertext_modulus: CiphertextModulus<C::Element>) -> Self {
        CRSLweBody {
            data: container,
            ciphertext_modulus,
        }
    }

    /// Return the [`CRSLweCodimension`] of the [`CRSLweBody`].
    ///
    /// See [`CRSLweBody::from_container`] for usage.//a faire?????
    /// to be adapted
    
    pub fn crs_lwe_codimension(&self) -> CRSLweCodimension{
        CRSLweCodimension(self.data.container_len())
    }

    /// Return the [`CiphertextModulus`] of the [`LweMask`].
    ///
    /// See [`LweMask::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }
    
    pub fn into_container(self) -> C {
        self.data
    }
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for CRSLweBody<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for CRSLweBody<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

//CRSLwe mask
#[derive(Clone, Debug)]
pub struct CRSLweMask<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

/// A convenience structure to easily manipulate the mask of a [`CRSLweCiphertext`].
impl<Scalar: UnsignedInteger, C: Container<Element = Scalar> > CRSLweMask<C> {
    /// Create a [`CRSLweMask`] from an existing container.
    ///
    /// # Note
    ///
    /// This docstring exhibits [`CRSLweMask`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for CRSLweMask creation
    /// let crs_lwe_dimension = CRSLweDimension(600);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// let crs_lwe_mask = CRSLweMask::from_container(vec![0u64; crs_lwe_dimension.0], ciphertext_modulus); //A regarder!!!!!!!!!!!!!!!!!!!!!
    ///
    /// assert_eq!(crs_lwe_mask.crs_lwe_dimension(), crs_lwe_dimension);
    /// assert_eq!(lwe_mask.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(container: C, ciphertext_modulus: CiphertextModulus<C::Element>) -> Self {
        CRSLweMask {
            data: container,
            ciphertext_modulus,
        }
    }

    /// Return the [`CRSLweDimension`] of the [`CRSLweMask`].
    ///
    /// See [`LweMask::from_container`] for usage.
    /// to be adapted
    
    pub fn crs_lwe_dimension(&self) -> CRSLweDimension {
        CRSLweDimension(self.data.container_len())
    }

    /// Return the [`CiphertextModulus`] of the [`LweMask`].
    ///
    /// See [`LweMask::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }
    pub fn into_container(self) -> C {
        self.data
    }
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for CRSLweMask<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for CRSLweMask<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }



    
}

/// A [`CRS LWE ciphertext`](`CRSLweCiphertext`).
///
/// # Formal Definition
///
/// ## CRS LWE Ciphertext
///
/// A CRS LWE ciphertext is an encryption of several plaintexts.
/// It is secure under the hardness assumption called Learning With Errors (LWE).//no idea
/// 
/// We indicate an LWE ciphertext of a plaintext $\mathsf{pt} \in\mathbb{Z}\_q$ as the following
/// couple: $$\mathsf{ct} = \left( \vec{a} , b\right) \in \mathsf{LWE}^n\_{\vec{s}}( \mathsf{pt}
/// )\subseteq \mathbb{Z}\_q^{(n+1)}$$ We call $q$ the ciphertext modulus and $n$ the LWE dimension.
///
/// ## CRS LWE dimension
/// It corresponds to the number of element in the CRS LWE secret key.
/// In a CRS LWE ciphertext, it is the length of the vector $\vec{a}$.
/// At [`encryption`](`crate::core_crypto::algorithms::encrypt_lwe_ciphertext`) time, it is
/// the number of uniformly random integers generated.
///
/// ## CRS LWE codimension
/// It corresponds to the number of element in the CRS LWE body.
///
/// ## LWE Encryption
/// ###### inputs:
/// - $\mathsf{pt}\in\mathbb{Z}\_q$: a plaintext
/// - $\vec{s}\in\mathbb{Z}\_q^n$: a secret key
/// - $\mathcal{D\_{\sigma^2,\mu}}$: a normal distribution of variance $\sigma^2$ and a mean $\mu$
///
/// ###### outputs:
/// - $\mathsf{ct} = \left( \vec{a} , b\right) \in \mathsf{LWE}^n\_{\vec{s}}( \mathsf{pt} )\subseteq
///   \mathbb{Z}\_q^{(n+1)}$: an LWE ciphertext
///
/// ###### algorithm:
/// 1. uniformly sample a vector $\vec{a}\in\mathbb{Z}\_q^n$
/// 2. sample an integer error term $e \hookleftarrow \mathcal{D\_{\sigma^2,\mu}}$
/// 3. compute $b = \left\langle \vec{a} , \vec{s} \right\rangle + \mathsf{pt} + e \in\mathbb{Z}\_q$
/// 4. output $\left( \vec{a} , b\right)$
///
/// ## LWE Decryption
/// ###### inputs:
/// - $\mathsf{ct} = \left( \vec{a} , b\right) \in \mathsf{LWE}^n\_{\vec{s}}( \mathsf{pt} )\subseteq
///   \mathbb{Z}\_q^{(n+1)}$: an LWE ciphertext
/// - $\vec{s}\in\mathbb{Z}\_q^n$: a secret key
///
/// ###### outputs:
/// - $\mathsf{pt}\in\mathbb{Z}\_q$: a plaintext
///
/// ###### algorithm:
/// 1. compute $\mathsf{pt} = b - \left\langle \vec{a} , \vec{s} \right\rangle \in\mathbb{Z}\_q$
/// 3. output $\mathsf{pt}$
///
/// **Remark:** Observe that the decryption is followed by a decoding phase that will contain a
/// rounding.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CRSLweCiphertext<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    codim: usize,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for CRSLweCiphertext<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
    
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for CRSLweCiphertext<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CRSLweCiphertext<C> {
    /// Create an [`LweCiphertext`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to encrypt data
    /// you need to use [`crate::core_crypto::algorithms::encrypt_lwe_ciphertext`] using this
    /// ciphertext as output.
    ///
    /// This docstring exhibits [`LweCiphertext`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for LweCiphertext creation
    /// let crs_lwe_size = CRSLweSize(600,5);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new LweCiphertext
    /// let mut crs_lwe = CRSLweCiphertext::new(0u64, crs_lwe_size, ciphertext_modulus);
    ///
    /// assert_eq!(crs_lwe.crs_lwe_size(), crs_lwe_size);
    /// assert_eq!(crs_lwe.get_mask().crs_lwe_dimension(), crs_lwe_size.to_lwe_dimension());
    /// assert_eq!(
    ///     crs_lwe.get_mut_mask().crs_lwe_dimension(),
    ///     crs_lwe_size.to_lwe_dimension()
    /// );
    /// assert_eq!(crs_lwe.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = crs_lwe.into_container();
    /// let codim =crs_lwe.codim
    /// // Recreate a ciphertext using from_container
    /// let mut crs_lwe = CRSLweCiphertext::from_container(underlying_container, ciphertext_modulus,codim);
    ///
    /// assert_eq!(crs_lwe.crs_lwe_size(), crs_lwe_size);
    /// assert_eq!(crs_lwe.get_mask().crs_lwe_dimension(), crs_lwe_size.to_lwe_dimension());
    /// assert_eq!(
    ///     crs_lwe.get_mut_mask().lwe_dimension(),
    ///     crs_lwe_size.to_lwe_dimension()
    /// );
    /// assert_eq!(lwe.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        ciphertext_modulus: CiphertextModulus<C::Element>,
        cod: usize,
    ) -> CRSLweCiphertext<C> {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create a CRSLweCiphertext"
        );
        CRSLweCiphertext {
            data: container,
            ciphertext_modulus,
            codim: cod,
        }
    }

    /// Return the [`CRSLweSize`] of the [`CRSLweCiphertext`]
    ///
    /// See [`LweCiphertext::from_container`] for usage.
    pub fn crs_lwe_size(&self) -> CRSLweSize {
        CRSLweSize(self.data.container_len(),self.codim)
    }

    /// Return immutable views to the [`CRSLweMask`] and [`CRSLweBody`] of a [`CRSLweCiphertext`].
    pub fn get_mask_and_body(&self) -> (CRSLweMask<&[Scalar]>, CRSLweBody<&[Scalar]>) {
        //let (body, mask) = self.data.as_ref().split_last().unwrap();
        let index = self.crs_lwe_size().to_crs_lwe_dimension().0;
        let (mask,body) = self.data.as_ref().split_at(index);
        let ciphertext_modulus = self.ciphertext_modulus();
        (
            CRSLweMask::from_container(mask, ciphertext_modulus),
            CRSLweBody::from_container(body, ciphertext_modulus),
        )
    }

    /// Return an immutable view to the [`CRSLweBody`] of an [`CRSLweCiphertext`].
    pub fn get_body(&self) -> CRSLweBody<&[Scalar]> {
        let index = self.crs_lwe_size().to_crs_lwe_dimension().0;
        CRSLweBody::from_container(
            &self.as_ref()[index..self.crs_lwe_size().0],
            self.ciphertext_modulus(),
        )
    }

    /// Return an immutable view to the [`CRSLweMask`] of an [`CRSLweCiphertext`].
    ///
    /// See [`LweCiphertext::from_container`] for usage.
    pub fn get_mask(&self) -> CRSLweMask<&[Scalar]> {
        CRSLweMask::from_container(
            &self.as_ref()[0..self.crs_lwe_size().to_crs_lwe_dimension().0],
            self.ciphertext_modulus(),
        )
    }

    /// Return a view of the [`CRSLweCiphertext`]. This is useful if an algorithm takes a view by
    /// value.
    pub fn as_view(&self) -> CRSLweCiphertextView<'_, Scalar> {
        CRSLweCiphertextView::from_container(self.as_ref(), self.ciphertext_modulus(), self.codim)
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`CRSLweCiphertext::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    /// Return the [`CiphertextModulus`] of the [`CRSLweCiphertext`].
    ///
    /// See [`CRSLweCiphertext::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> CRSLweCiphertext<C> {
    /// Mutable variant of [`CRSLweCiphertext::get_mask_and_body`].
    pub fn get_mut_mask_and_body(&mut self) -> (CRSLweMask<&mut [Scalar]>, CRSLweBody<&mut [Scalar]>) {
        let index = self.crs_lwe_size().to_crs_lwe_dimension().0;
        let ciphertext_modulus = self.ciphertext_modulus();
        let (mask,body) = self.data.as_mut().split_at_mut(index);  
        (
            CRSLweMask::from_container(mask, ciphertext_modulus),
            CRSLweBody::from_container(body, ciphertext_modulus),
        )
    }

    /// Mutable variant of [`CRSLweCiphertext::get_body`].
    pub fn get_mut_body(&mut self) -> CRSLweBody<&mut [Scalar]> {
        let indexi = self.crs_lwe_size().to_crs_lwe_dimension().0;
        let indexf = self.crs_lwe_size().0;
        let ciphertext_modulus = self.ciphertext_modulus();
        CRSLweBody::from_container(&mut self.as_mut()[indexi..indexf], ciphertext_modulus)
    }

    /// Mutable variant of [`CRSLweCiphertext::get_mask`].
    ///
    /// See [`LweCiphertext::from_container`] for usage.
    pub fn get_mut_mask(&mut self) -> CRSLweMask<&mut [Scalar]> {
        let crs_lwe_dimension = self.crs_lwe_size().to_crs_lwe_dimension();
        let ciphertext_modulus = self.ciphertext_modulus();
        CRSLweMask::from_container(&mut self.as_mut()[0..crs_lwe_dimension.0], ciphertext_modulus)
    }

    /// Mutable variant of [`CRSLweCiphertext::as_view`].
    pub fn as_mut_view(&mut self) -> CRSLweCiphertextMutView<'_, Scalar> {
        let ciphertext_modulus = self.ciphertext_modulus();
        let cod=self.codim;
        CRSLweCiphertextMutView::from_container(self.as_mut(), ciphertext_modulus,cod)
    }
}

/// A [`LweCiphertext`] owning the memory for its own storage.
pub type CRSLweCiphertextOwned<Scalar> = CRSLweCiphertext<Vec<Scalar>>;
/// A [`LweCiphertext`] immutably borrowing memory for its own storage.
pub type CRSLweCiphertextView<'data, Scalar> = CRSLweCiphertext<&'data [Scalar]>;
/// A [`LweCiphertext`] mutably borrowing memory for its own storage.
pub type CRSLweCiphertextMutView<'data, Scalar> = CRSLweCiphertext<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> CRSLweCiphertextOwned<Scalar> {
    /// Allocate memory and create a new owned [`CRSLweCiphertext`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to encrypt data you need to use
    /// [`crate::core_crypto::algorithms::encrypt_lwe_ciphertext`] using this ciphertext as
    /// output.
    ///
    /// See [`LweCiphertext::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        crs_lwe_size: CRSLweSize,
        ciphertext_modulus: CiphertextModulus<Scalar>,
        cod: usize,
    ) -> CRSLweCiphertextOwned<Scalar> {
        CRSLweCiphertextOwned::from_container(vec![fill_with; crs_lwe_size.0], ciphertext_modulus,cod)
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create [`CRSLweCiphertext`] entities.// didn't check what it was doing
#[derive(Clone, Copy)]
pub struct CRSLweCiphertextCreationMetadata<Scalar: UnsignedInteger>(pub CiphertextModulus<Scalar>, pub usize);

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C> for CRSLweCiphertext<C> {
    type Metadata = CRSLweCiphertextCreationMetadata<C::Element>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> CRSLweCiphertext<C> {
        let CRSLweCiphertextCreationMetadata(modulus,codim) = meta;
        CRSLweCiphertext::from_container(from, modulus,codim)
    }
}
