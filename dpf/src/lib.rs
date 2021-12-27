//! A crate implementing various distributed point function schemes
use ark_ff::Field;
use rand::{CryptoRng, RngCore};
use std::error::Error;

/// DPF scheme based on [[BGI18]].
///
/// [BGI18]: https://www.iacr.org/archive/eurocrypt2015/90560300/90560300.pdf
pub mod bgi18;

#[cfg(test)]
pub(crate) mod tests;

/// Describes the interface for a distributed point function scheme over some field. Such a scheme
/// allows a sender to generate two keys which provide succinct representations of functions
/// which output additive secret shares of the point function.
pub trait DPF<F: Field> {
    /// A succinct representation of a function which outputs shares of the underlying point
    /// function
    type Key;

    /// Takes the description of a point function as input -- where the point is a field element --
    /// and outputs two `Key`s.
    fn gen<RNG: CryptoRng + RngCore>(
        domain: usize,
        point: usize,
        val: F,
        rng: &mut RNG,
    ) -> Result<(Self::Key, Self::Key), Box<dyn Error>>;

    /// Takes a `Key` and point as input, and outputs a secret share of the point function at
    /// that point.
    fn eval(key: &Self::Key, point: usize) -> Result<F, Box<dyn Error>>;
}
