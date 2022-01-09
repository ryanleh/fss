use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize as Deserialize, CanonicalSerialize as Serialize, *};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use std::{marker::PhantomData, rc::Rc, vec::Vec};

use crate::{Pair, Seed};

/// A succinct representation of a function which outputs additive shares of
/// a point function evaluation
#[derive(Clone, Serialize, Deserialize)]
pub struct Key<F: Field, S: Seed> {
    pub log_domain: usize,
    pub root: Node<S>,
    pub codewords: Rc<Vec<Pair<CodeWord<S>>>>,
    pub mask: F,
}

/// A node in the DPF tree is composed of a seed and control-bit corresponding to each child node
#[derive(Copy, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Node<S: Seed> {
    pub seeds: Pair<S>,
    pub control_bits: Pair<bool>,
}

/// `CodeWord`s have the same structure as a `Node` but they are masking values, not the actual
/// seed/control-bit values.
pub type CodeWord<S> = Node<S>;

/// `MaskedNode`s have the same structure as a `Node`s but they are masked
/// values, not the actual seed/control-bit values.
pub(super) struct MaskedNode<PRG, S: Seed>
where
    PRG: CryptoRng + RngCore + SeedableRng<Seed = S>,
{
    pub masked_seeds: Pair<S>,
    pub masked_control_bits: Pair<bool>,
    _prg: PhantomData<PRG>,
}

impl<PRG, S: Seed> MaskedNode<PRG, S>
where
    PRG: CryptoRng + RngCore + SeedableRng<Seed = S>,
{
    /// Given an `IntermediateNode`, and the next bit index which will be evaluated, sample the
    /// `MaskedNode` corresponding to the next node in the DPF evaluation path
    #[inline]
    pub(super) fn sample_masked_node(node: &IntermediateNode<PRG::Seed>) -> Self {
        let mut prg = PRG::from_seed(node.seed);

        // Sample masked seeds.
        let mut masked_seeds = Pair::<S>::default();
        prg.fill_bytes(masked_seeds[0].as_mut());
        prg.fill_bytes(masked_seeds[1].as_mut());

        // Sample masked control-bits
        let mut masked_control_bits = Pair::<bool>::default();
        masked_control_bits[0] = prg.gen_bool(0.5);
        masked_control_bits[1] = prg.gen_bool(0.5);

        Self {
            masked_seeds,
            masked_control_bits,
            _prg: PhantomData,
        }
    }
}

/// An intermediate node in the DPF tree during evaluation where we know which seed/control-bit is
/// going to be selected.
///
/// Note this is simply a memory optimization, since we still need to fully evaluate the PRG for
/// correctness
pub(super) struct IntermediateNode<S: Seed> {
    pub seed: S,
    pub control_bit: bool,
}

impl<S: Seed> IntermediateNode<S> {
    /// Construct `Self` from a `Node` and a given bit
    pub(super) fn new(bit: bool, node: &Node<S>) -> Self {
        IntermediateNode {
            seed: node.seeds[bit],
            control_bit: node.control_bits[bit],
        }
    }

    /// Unmask the provided `MaskedNode` at `bit_idx` using `codeword`
    #[inline]
    pub(super) fn unmask_node<PRG>(
        bit: bool,
        mut masked_node: MaskedNode<PRG, S>,
        codeword: &CodeWord<S>,
    ) -> Self
    where
        PRG: CryptoRng + RngCore + SeedableRng<Seed = S>,
    {
        // XOR `masked_node` with `codeword` in-place and return it. This is fine since
        // `MaskedNode` and `IntermediateNode` are the same underlying type
        masked_node.masked_seeds[bit]
            .as_mut()
            .iter_mut()
            .zip(codeword.seeds[bit].as_ref())
            .for_each(|(s, cs)| *s ^= cs);
        masked_node.masked_control_bits[bit] ^= codeword.control_bits[bit];
        Self {
            seed: masked_node.masked_seeds[bit],
            control_bit: masked_node.masked_control_bits[bit],
        }
    }
}
