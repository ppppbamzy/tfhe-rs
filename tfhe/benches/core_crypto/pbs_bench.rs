use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rayon::prelude::*;
use tfhe::boolean::parameters::{BooleanParameters, DEFAULT_PARAMETERS, TFHE_LIB_PARAMETERS};
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::keycache::NamedParam;
use tfhe::shortint::parameters::*;
use tfhe::shortint::Parameters;

const VECTOR_SCALING_FACTOR: usize = 10;

const SHORTINT_BENCH_PARAMS: [Parameters; 15] = [
    PARAM_MESSAGE_1_CARRY_0,
    PARAM_MESSAGE_1_CARRY_1,
    PARAM_MESSAGE_2_CARRY_0,
    PARAM_MESSAGE_2_CARRY_1,
    PARAM_MESSAGE_2_CARRY_2,
    PARAM_MESSAGE_3_CARRY_0,
    PARAM_MESSAGE_3_CARRY_2,
    PARAM_MESSAGE_3_CARRY_3,
    PARAM_MESSAGE_4_CARRY_0,
    PARAM_MESSAGE_4_CARRY_3,
    PARAM_MESSAGE_4_CARRY_4,
    PARAM_MESSAGE_5_CARRY_0,
    PARAM_MESSAGE_6_CARRY_0,
    PARAM_MESSAGE_7_CARRY_0,
    PARAM_MESSAGE_8_CARRY_0,
];

const BOOLEAN_BENCH_PARAMS: [(&str, BooleanParameters); 2] = [
    ("boolean_default_params", DEFAULT_PARAMETERS),
    ("boolean_tfhe_lib_params", TFHE_LIB_PARAMETERS),
];

criterion_group!(
    pbs_group,
    mem_optimized_pbs::<u32>,
    mem_optimized_pbs::<u64>,
);

criterion_main!(pbs_group);

struct BenchmarkPbsParameters {
    input_lwe_dimension: LweDimension,
    lwe_modular_std_dev: StandardDev,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
}

impl From<BooleanParameters> for BenchmarkPbsParameters {
    fn from(params: BooleanParameters) -> Self {
        BenchmarkPbsParameters {
            input_lwe_dimension: params.lwe_dimension,
            lwe_modular_std_dev: params.lwe_modular_std_dev,
            decomp_base_log: params.pbs_base_log,
            decomp_level_count: params.pbs_level,
            glwe_dimension: params.glwe_dimension,
            polynomial_size: params.polynomial_size,
        }
    }
}

impl From<Parameters> for BenchmarkPbsParameters {
    fn from(params: Parameters) -> Self {
        BenchmarkPbsParameters {
            input_lwe_dimension: params.lwe_dimension,
            lwe_modular_std_dev: params.lwe_modular_std_dev,
            decomp_base_log: params.pbs_base_log,
            decomp_level_count: params.pbs_level,
            glwe_dimension: params.glwe_dimension,
            polynomial_size: params.polynomial_size,
        }
    }
}

fn benchmark_parameters<Scalar: Numeric>() -> Vec<(String, BenchmarkPbsParameters)> {
    if Scalar::BITS == 64 {
        SHORTINT_BENCH_PARAMS
            .iter()
            .map(|params| {
                (
                    format!("shortint_{}", params.name().to_lowercase()),
                    params.to_owned().into(),
                )
            })
            .collect()
    } else if Scalar::BITS == 32 {
        BOOLEAN_BENCH_PARAMS
            .iter()
            .map(|(name, params)| (name.to_string(), params.to_owned().into()))
            .collect()
    } else {
        vec![]
    }
}

fn mem_optimized_pbs<Scalar: UnsignedTorus + CastInto<usize> + Sync + Send>(c: &mut Criterion) {
    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

    for (cpus_kind, cpus_number) in (vec![
        ("logical", num_cpus::get()),
        ("physical", num_cpus::get_physical()),
    ])
    .iter()
    {
        rayon::ThreadPoolBuilder::new()
            .num_threads(*cpus_number)
            .build()
            .unwrap();

        for (name, params) in benchmark_parameters::<Scalar>().iter() {
            // Create the LweSecretKey
            let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
                params.input_lwe_dimension,
                &mut secret_generator,
            );
            let output_glwe_secret_key: GlweSecretKeyOwned<Scalar> =
                allocate_and_generate_new_binary_glwe_secret_key(
                    params.glwe_dimension,
                    params.polynomial_size,
                    &mut secret_generator,
                );
            let output_lwe_secret_key = output_glwe_secret_key.into_lwe_secret_key();

            // Create the empty bootstrapping key in the Fourier domain
            let fourier_bsk = FourierLweBootstrapKey::new(
                params.input_lwe_dimension,
                params.glwe_dimension.to_glwe_size(),
                params.polynomial_size,
                params.decomp_base_log,
                params.decomp_level_count,
            );

            let accumulator = GlweCiphertext::new(
                Scalar::ZERO,
                params.glwe_dimension.to_glwe_size(),
                params.polynomial_size,
            );

            let fft = Fft::new(fourier_bsk.polynomial_size());
            let fft = fft.as_view();

            let capacity = *cpus_number * VECTOR_SCALING_FACTOR;
            let mut input_vec: Vec<LweCiphertextOwned<Scalar>> = Vec::with_capacity(capacity);
            let mut output_vec: Vec<LweCiphertextOwned<Scalar>> = Vec::with_capacity(capacity);
            let mut buffers_vec: Vec<ComputationBuffers> = Vec::with_capacity(capacity);
            for _ in 0..(input_vec.capacity()){
                // Allocate new LweCiphertext and encrypt our plaintext
                input_vec.push(allocate_and_encrypt_new_lwe_ciphertext(
                    &input_lwe_secret_key,
                    Plaintext(Scalar::ZERO),
                    params.lwe_modular_std_dev,
                    &mut encryption_generator,
                ));

                // Allocate LweCiphertexts to store the result of the PBS
                output_vec.push(LweCiphertext::new(
                    Scalar::ZERO,
                    output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                ));

                let mut buffers = ComputationBuffers::new();
                buffers.resize(
                    programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<Scalar>(
                        fourier_bsk.glwe_size(),
                        fourier_bsk.polynomial_size(),
                        fft,
                    )
                    .unwrap()
                    .unaligned_bytes_required(),
                );
                buffers_vec.push(buffers);
            }

            let id = format!("PBS_mem-optimized_{name}_{cpus_number}_{cpus_kind}_cpus");
            #[allow(clippy::unit_arg)]
            {
                c.bench_function(&id, |b| {
                    b.iter(|| {
                        input_vec
                            .par_iter()
                            .zip(output_vec.par_iter_mut())
                            .zip(buffers_vec.par_iter_mut())
                            .for_each(|((input_ct, output_ct), buffers)| {
                                programmable_bootstrap_lwe_ciphertext_mem_optimized(
                                    input_ct,
                                    output_ct,
                                    &accumulator.as_view(),
                                    &fourier_bsk,
                                    fft,
                                    buffers.stack(),
                                )
                            });
                        black_box(&output_vec);
                    })
                });
            }
        }
    }
}
