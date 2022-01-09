use ark_ff::{
    BigInteger64 as BigInteger, FftParameters, Fp64, Fp64Parameters, FpParameters, One,
    UniformRand, Zero,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::test_rng;
use rand::{Rng, RngCore};
use rand_chacha::ChaChaRng;
use std::rc::Rc;

use crate::{
    point::{bgi18::*, DPF},
    Pair,
};

// Set field, seed, and PRG types
type F = Fp64<FParameters>;
type S = [u8; 32];
type PRG = ChaChaRng;

// Aliases for various DPF types
type BGI18 = super::bgi18::BGI18<F, PRG, S>;

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

fn test_correctness_helper<D: DPF<F>>() {
    let mut rng = test_rng();

    for log_domain in 2usize..12 {
        // Generate a random point in the given domain and field value
        let valid_range = 0..(1 << log_domain);
        let x = rng.gen_range(valid_range.clone());
        let y = F::rand(&mut rng);

        // Create the DPF
        let func = (log_domain, x, y);
        let (key1, key2) = D::gen(&func, &mut rng).unwrap();

        // Evaluate each point of the DPF
        for p in valid_range {
            let p1_result = D::eval(&key1, &p).unwrap();
            let p2_result = D::eval(&key2, &p).unwrap();
            if p == x {
                assert!(D::decode((&p1_result, &p2_result)).unwrap() == y)
            } else {
                assert!(D::decode((&p1_result, &p2_result)).unwrap() == F::zero())
            }
        }
    }
}

fn test_bad_inputs_helper<D: DPF<F>>() {
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

fn gen_rand_codeword<R: RngCore + Rng>(rng: &mut R) -> CodeWord<S> {
    let mut seeds = Pair::<S>::default();
    rng.fill_bytes(seeds[0].as_mut());
    rng.fill_bytes(seeds[1].as_mut());

    let mut control_bits = Pair::<bool>::default();
    control_bits[0] = rng.gen_bool(0.5);
    control_bits[1] = rng.gen_bool(0.5);
    CodeWord {
        seeds,
        control_bits,
    }
}

#[test]
fn test_correctness() {
    super::tests::test_correctness_helper::<BGI18>();
}

#[test]
fn test_bad_inputs() {
    super::tests::test_bad_inputs_helper::<BGI18>();
}

#[test]
fn test_serialization() {
    let mut rng = test_rng();
    let seed_len = S::default().len();

    // --------------
    // ---- Pair ----
    // --------------

    // Create seed and bit Pairs
    let mut seeds = Pair::<S>::default();
    rng.fill_bytes(seeds[0].as_mut());
    rng.fill_bytes(seeds[1].as_mut());

    let mut control_bits = Pair::<bool>::default();
    control_bits[0] = rng.gen_bool(0.5);
    control_bits[1] = rng.gen_bool(0.5);

    // Serialize the pairs and assert the correct lengths
    let mut serialized_seeds = vec![0; seeds.serialized_size()];
    let mut serialized_bits = vec![0; control_bits.serialized_size()];
    seeds.serialize(&mut serialized_seeds[..]).unwrap();
    control_bits.serialize(&mut serialized_bits[..]).unwrap();
    assert!(serialized_bits.len() == 1);
    assert!(serialized_seeds.len() == seed_len * 2);

    // Deserialize the Pairs and ensure they're unchanged
    let recovered_seeds = <Pair<S>>::deserialize(serialized_seeds.as_slice()).unwrap();
    let recovered_bits = <Pair<bool>>::deserialize(serialized_bits.as_slice()).unwrap();
    assert!(seeds == recovered_seeds);
    assert!(control_bits == recovered_bits);

    // ---------------
    // --- Node ---
    // ---------------

    // Use that pair as a root to test Node
    let root = Node {
        seeds,
        control_bits,
    };

    // Serialize the node and assert the correct length
    let mut serialized_root = vec![0; root.serialized_size()];
    root.serialize(&mut serialized_root[..]).unwrap();
    assert!(serialized_root.len() == seed_len * 2 + 1);

    // Deserialize the node and assert that it's unchanged
    let recovered_root = <Node<S>>::deserialize(serialized_root.as_slice()).unwrap();
    assert!(root == recovered_root);

    // ---------------
    // ----- Key -----
    // ---------------

    // Generate the key
    let log_domain = 20;
    let mut codewords = Vec::new();
    for _ in 0..log_domain - 1 {
        codewords.push(Pair::new(
            gen_rand_codeword(&mut rng),
            gen_rand_codeword(&mut rng),
        ));
    }
    let key = Key {
        log_domain,
        root,
        codewords: Rc::new(codewords),
        mask: F::rand(&mut rng),
    };

    // Serialize the node. The size can be variable here since the field element may be compressed
    let mut serialized_key = vec![0; key.serialized_size()];
    key.serialize(&mut serialized_key[..]).unwrap();

    // Deserialize the node and assert that it's unchanged
    let recovered_key = <Key<F, S>>::deserialize(serialized_key.as_slice()).unwrap();
    assert!(key.log_domain == recovered_key.log_domain);
    assert!(key.root == recovered_key.root);
    assert!(key.codewords == recovered_key.codewords);
    assert!(key.mask == recovered_key.mask);
}
