#![feature(min_specialization)]
use ark_serialize::{CanonicalDeserialize as Deserialize, CanonicalSerialize as Serialize};
use rand::{CryptoRng, RngCore};
use std::error::Error;

pub mod interval;
pub mod point;

pub mod tree;

pub mod data_structures;
pub use data_structures::*;

/// Describes the interface for a function secret sharing scheme. Such a scheme
/// allows a sender to generate keys which provide succinct representations of functions
/// which output secret shares of the underlying function.
///
/// Currently this only supports 2-party FSS schemes.
pub trait FSS {
    /// A succinct representation of a function which outputs shares of the underlying function
    type Key: Serialize + Deserialize;

    /// A description of the underlying function
    type Description;

    /// The domain of the underlying function
    type Domain;

    /// The range of the underlying function
    type Range;

    /// A secret share of the evaluation of the underlying function at a point
    type Share;

    /// Takes the description of an interval function as input -- where the value is a field element --
    /// and outputs two `Key`s.
    fn gen<RNG: CryptoRng + RngCore>(
        f: &Self::Description,
        rng: &mut RNG,
    ) -> Result<(Self::Key, Self::Key), Box<dyn Error>>;

    /// Takes a `Key` and point as input, and outputs a secret share of the underlying function at
    /// that point.
    fn eval(key: &Self::Key, point: &Self::Domain) -> Result<Self::Share, Box<dyn Error>>;

    /// Takes the secret shares as input, and outputs the corresponding function value.
    fn decode(shares: (&Self::Share, &Self::Share)) -> Result<Self::Range, Box<dyn Error>>;
}

/// Helper function to convert a `usize` to a vector of bools in big endian format
#[inline]
fn usize_to_bits(log_domain: usize, val: usize) -> Result<Vec<bool>, Box<dyn Error>> {
    // Ensure that the point is valid in the given domain
    if val >= (1 << log_domain) {
        return Err("Input point is not contained in provided domain")?;
    }

    let mut bits = Vec::new();
    bits.reserve(log_domain - 1);

    // Compute the little-endian bit-decomposition
    let bytes = val.to_le_bytes();
    for i in 0..log_domain {
        let mask = 1 << (i % 8);
        let bit = mask & bytes[(i / 8) as usize];
        bits.push(bit != 0);
    }

    // Convert to big-endian and return
    bits.reverse();
    Ok(bits)
}
