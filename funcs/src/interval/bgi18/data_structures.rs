use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize as Deserialize, CanonicalSerialize as Serialize, *};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use std::{marker::PhantomData, rc::Rc, vec::Vec};

use crate::{Pair, Seed};

/// A succinct representation of a function which outputs additive shares of
/// an interval function evaluation
#[derive(Clone, Serialize, Deserialize)]
pub struct Key<F: Field, S: Seed> {
    pub log_domain: usize,
    pub root: Node<F, S>,
    pub codewords: Rc<Vec<Pair<CodeWord<F, S>>>>,
}

/// A node in the DIF tree is composed of a seed, control-bit, and field element corresponding to
/// each child node
#[derive(Copy, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Node<F: Field, S: Seed> {
    pub seeds: Pair<S>,
    pub control_bits: Pair<bool>,
    pub elems: Pair<F>,
}

/// `CodeWord`s have the same structure as a `Node` but they are masking values, not the actual
/// seed/control-bit values.
pub type CodeWord<F, S> = Node<F, S>;

/// `MaskedNode`s have the same structure as a `Node`s but they are masked values, not the
/// actual seed/control-bit values.
pub(super) struct MaskedNode<PRG, F: Field, S: Seed>
where
    PRG: CryptoRng + RngCore + SeedableRng<Seed = S>,
{
    pub masked_seeds: Pair<S>,
    pub masked_control_bits: Pair<bool>,
    pub masked_elems: Pair<F>,
    _prg: PhantomData<PRG>,
}

impl<PRG, F: Field, S: Seed> MaskedNode<PRG, F, S>
where
    PRG: CryptoRng + RngCore + SeedableRng<Seed = S>,
{
    /// Given an `IntermediateNode`, and the next bit index which will be evaluated, sample the
    /// `MaskedNode` corresponding to the next node in the DIF evaluation path
    #[inline]
    pub(super) fn sample_masked_node(node: &IntermediateNode<F, PRG::Seed>) -> Self {
        let mut prg = PRG::from_seed(node.seed);

        // Sample masked seeds.
        let mut masked_seeds = Pair::<S>::default();
        prg.fill_bytes(masked_seeds[0].as_mut());
        prg.fill_bytes(masked_seeds[1].as_mut());

        // Sample masked control-bits
        let mut masked_control_bits = Pair::<bool>::default();
        masked_control_bits[0] = prg.gen_bool(0.5);
        masked_control_bits[1] = prg.gen_bool(0.5);

        // Sample masked field elems
        let mut masked_elems = Pair::<F>::default();
        masked_elems[0] = F::rand(&mut prg);
        masked_elems[1] = F::rand(&mut prg);

        Self {
            masked_seeds,
            masked_control_bits,
            masked_elems,
            _prg: PhantomData,
        }
    }
}
