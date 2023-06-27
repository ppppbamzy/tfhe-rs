
//use super::*;

//use crate::core_crypto::commons::generators::{DeterministicSeeder, EncryptionRandomGenerator, SecretRandomGenerator,};
//use crate::core_crypto::commons::math::random::{ActivatedRandomGenerator, CompressionSeed};
//use crate::core_crypto::commons::test_tools;
use concrete_csprng::generators::SoftwareRandomGenerator;
use concrete_csprng::seeders::Seed;
use crate::core_crypto::commons::math::random::RandomGenerator;
use crate::core_crypto::prelude::*;
use crate::core_crypto::prelude::slice_algorithms::slice_wrapping_dot_product;

  

fn integer_round(lwe: u64, log_poly_size: u64, ciphertext_modulus_log: usize) -> u64 {
    let mut res = lwe;
    // Start doing the right shift
    res >>= ciphertext_modulus_log - log_poly_size as usize - 1_usize;
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

fn change_modulus_ciphertext<Scalar, InputCont>(
    crs_lwe_ciphertext: &mut CRSLweCiphertext<InputCont>,
    old_modulus_log: usize,
    new_modulus_log: usize, 
)where   
Scalar: UnsignedInteger,
InputCont: ContainerMut<Element = Scalar>,
{
    let decomposer:SignedDecomposer<Scalar> = SignedDecomposer::new(DecompositionBaseLog(64-old_modulus_log+new_modulus_log), DecompositionLevelCount(1));
    let  (mut mask, mut body) = crs_lwe_ciphertext.get_mut_mask_and_body();
    let mask_mut=mask.as_mut();
    let body_mut = body.as_mut();
    mask_mut.iter_mut().for_each(|elt| *elt = decomposer.closest_representable(*elt));
    body_mut.iter_mut().for_each(|elt| *elt = decomposer.closest_representable(*elt));
    crs_lwe_ciphertext.set_ciphertext_modulus(new_modulus_log);//maybe useless
}

fn change_modulus_plaintext<Scalar>(
    plaintext_list : & mut PlaintextList<Vec<Scalar>>,
    old_modulus_log: usize,
    new_modulus_log: usize, 
)where   
Scalar: UnsignedInteger,
{
    let decomposer:SignedDecomposer<Scalar> = SignedDecomposer::new(DecompositionBaseLog(64-old_modulus_log+new_modulus_log), DecompositionLevelCount(1));
    let text_mut = plaintext_list.as_mut();
    text_mut.iter_mut().for_each(|elt| *elt = decomposer.closest_representable(*elt));
}


fn remove_text_and_mask<Scalar, KeyCont, InputCont>(
    crs_lwe_secret_key: &CRSLweSecretKey<KeyCont>,
    crs_lwe_ciphertext: &mut CRSLweCiphertext<InputCont>,
    plaintext_list : &PlaintextList<Vec<Scalar>>,
)
where   
    Scalar: UnsignedInteger,
    KeyCont: Container<Element = Scalar>,
    InputCont: ContainerMut<Element = Scalar>,

{
    
    let key_ref = crs_lwe_secret_key.as_ref();
    let keys = key_ref.split_into(crs_lwe_ciphertext.crs_lwe_size().1 );
    
    let (mask, mut body)= crs_lwe_ciphertext.get_mut_mask_and_body();
    let bodies_mut = body.as_mut();
    let mask_ref =mask.as_ref();
        
    let text_list = plaintext_list.as_ref();
    
    // Subtract the mask x key

    bodies_mut.iter_mut().zip(keys).for_each(|(body, key_chunk)| *body = (*body).wrapping_sub(slice_wrapping_dot_product(
        mask_ref,
        key_chunk,
    )) );
    
    //for a in bodies_mut.iter(){
    //    println!("{:#066b}",a);        
    //}

    //println!("{:?}",body.data[1]);
    // Subtract the message in the list
    bodies_mut.iter_mut().zip(text_list).for_each(|(bod,text)| *bod =(*bod).wrapping_sub(*text));
   
    /* 
    for a in bodies_mut.iter(){
        println!("{:#066b}",a);        
    }
     // */   
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


fn test_covariance(dimension:usize,error: f64)->(f64,f64,f64,f64,f64,f64,f64,f64,f64){

    let crs_lwe_dimension = CRSLweDimension(dimension);
    let crs_lwe_codimension = CRSLweCodimension(2);
    let crs_lwe_modular_std_dev = StandardDev(error);
    //let crs_lwe_modular_std_dev = StandardDev(0.0);
    //let crs_lwe_modular_std_dev = StandardDev(0.000007069849454709433);
    // pb a partir de 0.0000000009313225746154785
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
        //*el=(*el).wrapping_add((i as u64)<<delta);
        *el = (*el).wrapping_add((1 as u64)<<delta);
    }
    // Create a CRSLweCiphertext list
    let number:usize= 100000;
    let mut ciph_list =vec![CRSLweCiphertext::new(0u64, crs_lwe_dimension.to_crs_lwe_size(crs_lwe_codimension), ciphertext_modulus);number];
    //0..number.map(|_|).collect())
    let old_mod:usize = 64;
    let new_mod:usize = 32;
    for i in 0..number{
        //generate the secret key for each cipher and write the text in the body slots
        let crs_lwe_secret_key =
            allocate_and_generate_new_binary_crs_lwe_secret_key(crs_lwe_dimension,crs_lwe_codimension, &mut secret_generator);
        encrypt_crs_lwe_ciphertext(
            &crs_lwe_secret_key,
            &mut ciph_list[i],
            plaintext_list.clone(),
            crs_lwe_modular_std_dev,
            &mut encryption_generator,
        );
         
        change_modulus_ciphertext(
            &mut ciph_list[i],
            old_mod,
            new_mod, 
        );
        //useless 
        /* 
        change_modulus_plaintext(
            & mut plaintext_list ,
            old_mod,
            new_mod, 
        );
        // */
        remove_text_and_mask(
            &crs_lwe_secret_key,
            &mut ciph_list[i],
            &plaintext_list,
        );    
          
    }
    let mut esp_x=0.0;
    let mut esp_y=0.0;
    let mut cov_xy=0.0;
    let mut var_x=0.0;
    let mut var_y=0.0;
    let mut sigma_x=0.0;
    let mut sigma_y=0.0;
    let decal = old_mod-new_mod;

    
  
    //Calculation of the expectation
   
    for i in 0..number{
        let body_ref=ciph_list[i].get_body();
        esp_x+= ((((body_ref.data[0])>>decal) as i32) as f64);
        esp_y+= ((((body_ref.data[1])>>decal)as i32) as f64);
    }
    esp_x/= (number as f64);
    esp_y/= (number as f64);
    
    //Calculation of the covariance, variances and standard deviation
    for i in 0..number{
        let body_ref=ciph_list[i].get_body();
         
        cov_xy+=((((body_ref.data[0])>>decal) as i32) as f64 -esp_x)*((((body_ref.data[1])>>decal) as i32) as f64 -esp_y);
        var_x +=((((body_ref.data[0])>>decal) as i32) as f64 -esp_x)*((((body_ref.data[0])>>decal) as i32) as f64 -esp_x);
        var_y +=((((body_ref.data[1])>>decal) as i32) as f64 -esp_y)*((((body_ref.data[1])>>decal) as i32) as f64 -esp_y);
        
    }
    cov_xy/=(number as f64-1.0);
    var_x /=(number as f64-1.0);
    var_y /=(number as f64-1.0);
    sigma_x=var_x.sqrt();
    sigma_y=var_y.sqrt();
    
    //correlation coefficient
    
    let cor_xy=cov_xy/(sigma_x*sigma_y);
    let ratio = 2.0.powi(-2*(decal as i32));
    let expected = (dimension as f64)*(1.0-ratio)/(48.0*ratio*(error)*(error)*2.0.powi(128)+4.0-4.0*ratio+(dimension as f64)*(2.0+ratio));
    let expected_cov=  (dimension as f64)*(1.0-ratio)/48.0;
    let expected_var = (48.0*ratio*(error)*(error)*2.0.powi(128)+4.0-4.0*ratio+(dimension as f64)*(2.0+ratio))/48.0;
    return (cov_xy,cor_xy,sigma_x,sigma_y,var_x,var_y,expected,expected_cov,expected_var);
       
}

/* 
#[test]
fn testy(){
    test_compare();
    
    panic!();
}
// */
#[test]
fn test_cov(){
    
    for j in 25..=30{
        //let error = 1.0/((1<<j) as f64);
        let error = 2.0.powi(-(j as i32));
        //let error = 0.0;
       
        println!("Error: {}",error);
        println!("j: {}",j);
        println!();
        for i in 700..701{
            
            println!();
            let (cov,corr, sigma_x, sigma_y, var_x, var_y,expected,expected_cov,expected_var) = test_covariance(i,error);
            println!("cov: {}",cov);
            println!("expected_cov: {}",expected_cov);
            println!("log_2 cov: {}",cov.log2());
            println!("log_2 expected_cov: {}",expected_cov.log2());
            println!("corr: {}",corr);
            println!("expected_corr: {}",expected);
            println!("expected_var: {}",expected_var);
            println!("var_x: {}",var_x);
            println!("var_y: {}",var_y);
            println!("expected_log_2 var: {}",expected_var.log2());
            println!("log_2 var_x: {}",var_x.log2());
            println!("log_2 var_y: {}",var_y.log2());
            
            //println!("sigma_x: {}",sigma_x);
            //println!("sigma_y: {}",sigma_y);

        }    
    }
    panic!();
}