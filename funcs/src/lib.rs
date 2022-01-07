#![feature(min_specialization)]
use ark_serialize::{CanonicalDeserialize as Deserialize, CanonicalSerialize as Serialize};
use rand::{CryptoRng, RngCore};
use std::error::Error;

pub mod point;

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
