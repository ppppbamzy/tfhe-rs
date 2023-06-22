
//use super::*;

//use crate::core_crypto::commons::generators::{DeterministicSeeder, EncryptionRandomGenerator, SecretRandomGenerator,};
//use crate::core_crypto::commons::math::random::{ActivatedRandomGenerator, CompressionSeed};
//use crate::core_crypto::commons::test_tools;
use concrete_csprng::generators::SoftwareRandomGenerator;
use concrete_csprng::seeders::Seed;
use crate::core_crypto::commons::math::random::RandomGenerator;
use crate::core_crypto::prelude::*;
//use crate::core_crypto::prelude::EncryptionRandomGenerator;
//use crate::core_crypto::prelude::SecretRandomGenerator;
//use crate::core_crypto::prelude::SignedDecomposer;
//use crate::core_crypto::prelude::DecompositionBaseLog;
//use crate::core_crypto::prelude::DecompositionLevelCount;
  

fn integer_round(lwe: u64, log_poly_size: u64, ciphertext_modulus_log: usize) -> u64 {
    let mut res = lwe;
    // Start doing the right shift
    res >>= ciphertext_modulus_log - log_poly_size as usize - 2_usize;
    // Do the rounding
    res += res & 1_u64;
    // Finish the right shift
    res >>= 1;
    res
}
fn print_binary(number: u64){
    let mut res=0;
    for i in 0..64{
        res = (number >> (63-i))&1;
        print!("{}",res);
    }
    println!();     
}

fn test_compare(){
    let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    let delta = 60u64;
    const NB_TESTS: usize = 100;
    let decomposer = SignedDecomposer::new(DecompositionBaseLog((64-delta) as usize), DecompositionLevelCount(1));
    for i in 0..NB_TESTS{
        let random = generator.random_uniform::<u64>();
        //let fl = (random as f64)/1000.;
        let round1= integer_round(random, 0 , 61);
        let round2 = decomposer.closest_representable(random);
        //println!("{}",fl);
        println!("random :{} {}",random,i);
        print_binary(random);
        println!("round1 {} random",round1);
        print_binary(round1);
        println!("round2 {} random",round2);
        print_binary(round2);        
    }    
 
}


fn test_covariance(){

    let crs_lwe_dimension = CRSLweDimension(742);
    let crs_lwe_codimension = CRSLweCodimension(2);
    let crs_lwe_modular_std_dev = StandardDev(0.000007069849454709433);
    //let crs_lwe_modular_std_dev = StandardDev(0.7069849454709433);
    let ciphertext_modulus = CiphertextModulus::new_native();

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
    EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
    //EncryptionRandomGenerator::<ByteRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

    // Create the plaintexts

    let msg = 0u64;
    let delta = 60u64;
    let mut plaintext_list = PlaintextList::new(msg, PlaintextCount(crs_lwe_codimension.0));
    let list = plaintext_list.as_mut();//question a arthur pourquoi je ne dois pas declarer let mut list
    for (i, el) in list.iter_mut().enumerate(){
    *el=(*el).wrapping_add((i as u64)<<delta);
    }
    // Create a CRSLweCiphertext list
    let number:usize= 10000;
    let mut cyph_list =vec![CRSLweCiphertext::new(0u64, crs_lwe_dimension.to_crs_lwe_size(crs_lwe_codimension), ciphertext_modulus);number];
    //0..number.map(|_|).collect())
    for i in 0..number{
        //generate the secret key for each cipher
        let crs_lwe_secret_key =
            allocate_and_generate_new_binary_crs_lwe_secret_key(crs_lwe_dimension,crs_lwe_codimension, &mut secret_generator);
        encrypt_crs_lwe_ciphertext(
            &crs_lwe_secret_key,
            &mut cyph_list[i],
            plaintext_list.clone(),
            crs_lwe_modular_std_dev,
            &mut encryption_generator,
        );    
    }

}

#[test]
fn testy(){
    test_compare();
    //panic!();
}
#[test]
fn test_cov(){
    test_covariance();
    panic!();
}