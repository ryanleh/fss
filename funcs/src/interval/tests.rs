use ark_ff::{
    BigInteger64 as BigInteger, FftParameters, Fp64, Fp64Parameters, FpParameters, One,
    UniformRand, Zero,
};
use ark_std::test_rng;
use rand::Rng;
use rand_chacha::ChaChaRng;

use crate::interval::{bgi15, DIF};

// Set field, seed, and PRG types
type F = Fp64<FParameters>;
type S = [u8; 32];
type PRG = ChaChaRng;

// Aliases for various DPF types
type BGI15 = bgi15::Bgi15DIF<F, PRG, S>;

// Define a field to use. This is the same 63-bit field used in
// "Lightweight Techniques for Private Heavy Hitters"
struct FParameters;

impl Fp64Parameters for FParameters {}
impl FftParameters for FParameters {
    type BigInt = BigInteger;
    const TWO_ADICITY: u32 = 1;
    const TWO_ADIC_ROOT_OF_UNITY: Self::BigInt = BigInteger([1]);
}

impl FpParameters for FParameters {
    const MODULUS: BigInteger = BigInteger([9223372036854775783]);
    const MODULUS_BITS: u32 = 63u32;
    const REPR_SHAVE_BITS: u32 = 1;
    const R: BigInteger = BigInteger([50]);
    const R2: BigInteger = BigInteger([2500]);
    const INV: u64 = 1106804644422573097;
    const GENERATOR: BigInteger = BigInteger([3]);
    const CAPACITY: u32 = Self::MODULUS_BITS - 1;
    const T: BigInteger = BigInteger([4611686018427387891]);
    const T_MINUS_ONE_DIV_TWO: BigInteger = BigInteger([2305843009213693945]);
    const MODULUS_MINUS_ONE_DIV_TWO: BigInteger = BigInteger([4611686018427387891]);
}

fn test_correctness_helper<D: DIF<F>>() {
    let mut rng = test_rng();

    for log_domain in 2usize..12 {
        // Generate a random point in the given domain and field value
        let valid_range = 0..(1 << log_domain);
        let x = rng.gen_range(valid_range.clone());
        let y = F::rand(&mut rng);

        // Create the DIF
        let func = (log_domain, x, y);
        let (key1, key2) = D::gen(&func, &mut rng).unwrap();

        // Evaluate each point of the DIF
        for p in valid_range.clone() {
            let p1_result = D::eval(&key1, &p).unwrap();
            let p2_result = D::eval(&key2, &p).unwrap();
            if p < x {
                assert!(D::decode((&p1_result, &p2_result)).unwrap() == y)
            } else {
                assert!(D::decode((&p1_result, &p2_result)).unwrap() == F::zero())
            }
        }
    }
}

fn test_bad_inputs_helper<D: DIF<F>>() {
    let mut rng = test_rng();
    let log_domain: usize = 10;
    let max = 1 << log_domain;
    let bad_range = max..2 * max;

    // Test Gen fail
    let x = rng.gen_range(bad_range.clone());
    let func = (log_domain, x, F::one());
    let result = D::gen(&func, &mut rng);
    assert!(result.is_err());

    // Test P1 Eval fail
    let x = rng.gen_range(0..max);
    let func = (log_domain, x, F::one());
    let (k1, k2) = D::gen(&func, &mut rng).unwrap();

    let p = rng.gen_range(bad_range);
    let result = D::eval(&k1, &p);
    assert!(result.is_err());

    let result = D::eval(&k2, &p);
    assert!(result.is_err());
}

#[test]
fn test_correctness() {
    super::tests::test_correctness_helper::<BGI15>();
}

#[test]
fn test_bad_inputs() {
    super::tests::test_bad_inputs_helper::<BGI15>();
}
