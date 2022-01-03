use ark_ff::{
    BigInteger64 as BigInteger, FftParameters, Field, Fp64, Fp64Parameters, FpParameters,
};
use ark_std::test_rng;
use criterion::{black_box, BenchmarkId, Criterion};
use rand::Rng;
use rand_chacha::ChaChaRng;

use fss_funcs::point::{bgi18, DPF};

#[macro_use]
extern crate criterion;

const LOG_DOMAIN_RANGE: [usize; 3] = [20, 25, 30];

// Set field, seed, and PRG types
type F = Fp64<FParameters>;
type S = [u8; 32];
type PRG = ChaChaRng;

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

fn dpf_gen_bench<F: Field, D: DPF<F>>(c: &mut Criterion) {
    let mut rng = test_rng();

    for log_domain in LOG_DOMAIN_RANGE {
        // Generate a random point in the given domain and field value
        let x = rng.gen_range(0..2usize.pow(log_domain as u32));
        let y = F::rand(&mut rng);
        let func = (log_domain, x, y);

        c.bench_with_input(BenchmarkId::new("Gen", log_domain), &log_domain, |b, _| {
            b.iter(|| black_box(D::gen(&func, &mut rng)))
        });
    }
}

fn dpf_eval_bench<F: Field, D: DPF<F>>(c: &mut Criterion) {
    let mut rng = test_rng();

    let mut group = c.benchmark_group("Eval");

    for log_domain in LOG_DOMAIN_RANGE {
        // Generate a random point in the given domain and field value
        let x = rng.gen_range(0..2usize.pow(log_domain as u32));
        let y = F::rand(&mut rng);
        let func = (log_domain, x, y);

        // Generate DPF keys
        let (k1, k2) = D::gen(&func, &mut rng).unwrap();

        // Random evaluation point
        let p = rng.gen_range(0..2usize.pow(log_domain as u32));

        group.bench_with_input(
            BenchmarkId::new("P1/Random", log_domain),
            &log_domain,
            |b, _| b.iter(|| black_box(D::eval(&k1, &p))),
        );

        group.bench_with_input(BenchmarkId::new("P1/X", log_domain), &log_domain, |b, _| {
            b.iter(|| black_box(D::eval(&k1, &x)))
        });

        group.bench_with_input(
            BenchmarkId::new("P2/Random", log_domain),
            &log_domain,
            |b, _| b.iter(|| black_box(D::eval(&k2, &p))),
        );

        group.bench_with_input(BenchmarkId::new("P2/X", log_domain), &log_domain, |b, _| {
            b.iter(|| black_box(D::eval(&k2, &x)))
        });
    }
    group.finish();
}

fn bench_dpf(c: &mut Criterion) {
    dpf_gen_bench::<F, bgi18::BGI18<F, PRG, S>>(c);
    dpf_eval_bench::<F, bgi18::BGI18<F, PRG, S>>(c);
}

criterion_group!(benches, bench_dpf);
criterion_main!(benches);
