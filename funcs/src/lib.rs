//! A crate for the SimplePIR preprocessing PIR schemes 
//!
//! TODO: Note some code taken from Henry's IDPF 

pub mod data_structures;
pub use data_structures::*;

pub mod group;
pub use group::*;

pub mod prg;
pub use prg::*;

pub mod bgi18;
pub use bgi18::*;

#[cfg(test)]
pub mod tests;

/// Describes the interface for a 2-party distributed point-function scheme.
pub trait DPF<G: Group> {
    /// A succinct representation of a distributed point function.
    type Key;

    /// Takes the description of an function as input and outputs the corresponding keys.
    fn gen(
        log_domain: usize,
        point: usize,
        value: G,
        prg: &mut PRG
    ) -> (Self::Key, Self::Key);

    /// Takes a `Key` and point as input, and outputs a secret share of the underlying function at
    /// that point.
    fn eval(key: &Self::Key, point: &[bool], prg: &mut PRG) -> G;

    /// Optimized version of `eval` when evaluating the DPF on the entire domain.
    fn eval_full(key: &Self::Key, prg: &mut PRG) -> Vec<G>;
}

/// Helper function to convert a `usize` to a vector of bools in big endian format
#[inline]
fn usize_to_bits(log_domain: usize, val: usize) -> Vec<bool> {
    debug_assert!(val < 1 << log_domain);

    let mut bits = Vec::new();
    bits.reserve(log_domain);

    // Compute the little-endian bit-decomposition
    let bytes = val.to_le_bytes();
    for i in 0..log_domain {
        let mask = 1 << (i % 8);
        let bit = mask & bytes[(i / 8) as usize];
        bits.push(bit != 0);
    }

    // Convert to big-endian and return
    bits.reverse();
    bits
}
