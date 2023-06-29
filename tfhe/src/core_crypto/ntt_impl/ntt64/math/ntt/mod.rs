use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulusKind;
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::prelude::*;
use concrete_ntt::prime64::Plan;
use once_cell::sync::OnceCell;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[derive(Clone, Debug)]
pub struct Ntt {
    plan: Arc<Plan>,
}

#[derive(Clone, Copy, Debug)]
pub struct NttView<'a> {
    pub(crate) plan: &'a Plan,
}

impl Ntt {
    #[inline]
    pub fn as_view(&self) -> NttView<'_> {
        NttView { plan: &self.plan }
    }
}

type PlanMap = RwLock<HashMap<usize, Arc<OnceCell<Arc<Plan>>>>>;
pub(crate) static PLANS: OnceCell<PlanMap> = OnceCell::new();
fn plans() -> &'static PlanMap {
    PLANS.get_or_init(|| RwLock::new(HashMap::new()))
}

impl Ntt {
    /// Real polynomial of size `size`.
    pub fn new(modulus: CiphertextModulus<u64>, size: PolynomialSize) -> Self {
        let global_plans = plans();

        assert_eq!(modulus.kind(), CiphertextModulusKind::NonNative);

        let n = size.0;
        let modulus = modulus.get_custom_modulus() as u64;
        let get_plan = || {
            let plans = global_plans.read().unwrap();
            let plan = plans.get(&n).cloned();
            drop(plans);

            plan.map(|p| {
                p.get_or_init(|| {
                    Arc::new(Plan::try_new(n, modulus).expect(&format!(
                        "could not generate an NTT plan for the given modulus ({})",
                        modulus,
                    )))
                })
                .clone()
            })
        };

        // could not find a plan of the given size, we lock the map again and try to insert it
        let mut plans = global_plans.write().unwrap();
        if let Entry::Vacant(v) = plans.entry(n) {
            v.insert(Arc::new(OnceCell::new()));
        }

        drop(plans);

        Self {
            plan: get_plan().unwrap(),
        }
    }
}

impl NttView<'_> {
    pub fn polynomial_size(self) -> PolynomialSize {
        PolynomialSize(self.plan.ntt_size())
    }

    pub fn custom_modulus(self) -> u64 {
        self.plan.modulus()
    }

    pub fn forward(self, ntt: PolynomialMutView<'_, u64>, standard: PolynomialView<'_, u64>) {
        let mut ntt = ntt;
        let ntt = ntt.as_mut();
        let standard = standard.as_ref();
        ntt.copy_from_slice(standard);
        self.plan.fwd(ntt);
    }

    pub fn forward_normalized(
        self,
        ntt: PolynomialMutView<'_, u64>,
        standard: PolynomialView<'_, u64>,
    ) {
        let mut ntt = ntt;
        let ntt = ntt.as_mut();
        let standard = standard.as_ref();
        ntt.copy_from_slice(standard);
        self.plan.fwd(ntt);
        self.plan.normalize(ntt);
    }

    pub fn add_backward(
        self,
        standard: PolynomialMutView<'_, u64>,
        ntt: PolynomialMutView<'_, u64>,
    ) {
        let mut ntt = ntt;
        let mut standard = standard;
        let ntt = ntt.as_mut();
        let standard = standard.as_mut();
        self.plan.inv(ntt);

        // autovectorize
        pulp::Arch::new().dispatch(
            #[inline(always)]
            || {
                for (out, inp) in izip!(standard, &*ntt) {
                    *out = u64::wrapping_add(*out, *inp);
                }
            },
        )
    }
}
