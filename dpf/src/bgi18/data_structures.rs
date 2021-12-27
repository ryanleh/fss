use ark_ff::Field;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use std::{
    marker::PhantomData,
    ops::{Index, IndexMut},
    rc::Rc,
    vec::Vec,
};

/// A succinct representation of a function which outputs additive shares of
/// a point function
#[derive(Clone)]
pub struct Key<F: Field, S: Seed> {
    pub log_domain: usize,
    pub root: DPFNode<S>,
    pub codewords: Rc<Vec<Pair<CodeWord<S>>>>,
    pub mask: F,
}

/// A node in the DPF tree is composed of a seed and control-bit corresponding to each child node
#[derive(Clone)]
pub struct DPFNode<S: Seed> {
    pub seeds: Pair<S>,
    pub control_bits: Pair<bool>,
}

/// `CodeWord`s have the same structure as a `DPFNode` but they are masking values, not the actual
/// seed/control-bit values.
pub type CodeWord<S> = DPFNode<S>;

/// `MaskedDPFNode`s have the same structure as a `DPFNode`s but they are masked
/// values, not the actual seed/control-bit values.
pub(super) struct MaskedDPFNode<PRG, S: Seed>
where
    PRG: CryptoRng + RngCore + SeedableRng<Seed = S>,
{
    pub masked_seeds: Pair<S>,
    pub masked_control_bits: Pair<bool>,
    _prg: PhantomData<PRG>,
}

impl<PRG, S: Seed> MaskedDPFNode<PRG, S>
where
    PRG: CryptoRng + RngCore + SeedableRng<Seed = S>,
{
    /// Given an `IntermediateDPFNode`, and the next bit index which will be evaluated, sample the
    /// `MaskedDPFNode` corresponding to the next node in the DPF evaluation path
    #[inline]
    pub(super) fn sample_masked_node(node: &IntermediateDPFNode<PRG::Seed>) -> Self {
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
pub(super) struct IntermediateDPFNode<S: Seed> {
    pub seed: S,
    pub control_bit: bool,
}

impl<S: Seed> IntermediateDPFNode<S> {
    /// Construct `Self` from a `DPFNode` and a given bit
    pub(super) fn new(bit: bool, node: &DPFNode<S>) -> Self {
        IntermediateDPFNode {
            seed: node.seeds[bit],
            control_bit: node.control_bits[bit],
        }
    }

    /// Unmask the provided `MaskedDPFNode` at `bit_idx` using `codeword`
    ///
    /// TODO: Can you use SIMD here
    #[inline]
    pub(super) fn unmask_node<PRG>(
        bit: bool,
        mut masked_node: MaskedDPFNode<PRG, S>,
        codeword: &CodeWord<S>,
    ) -> Self
    where
        PRG: CryptoRng + RngCore + SeedableRng<Seed = S>,
    {
        // XOR `masked_node` with `codeword` in-place and return it. This is fine since
        // `MaskedDPFNode` and `IntermediateDPFNode` are the same underlying type
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

/// A PRG seed
pub trait Seed: Sized + Default + Copy + AsRef<[u8]> + AsMut<[u8]> {}
impl Seed for [u8; 16] {}
impl Seed for [u8; 32] {}

/// A container for two identical-type objects which can be indexed using `bool`
#[derive(Clone, Default)]
pub struct Pair<T> {
    val: [T; 2],
}

impl<T> Pair<T> {
    pub fn new(first: T, second: T) -> Self {
        Self {
            val: [first, second],
        }
    }
}

impl<T: Sized + Clone> Index<usize> for Pair<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        assert!(index == 0 || index == 1);
        &self.val[index]
    }
}

impl<T: Sized + Clone> IndexMut<usize> for Pair<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        assert!(index == 0 || index == 1);
        &mut self.val[index]
    }
}

impl<T: Sized + Clone> Index<bool> for Pair<T> {
    type Output = T;

    fn index(&self, index: bool) -> &Self::Output {
        &self.val[index as usize]
    }
}

impl<T: Sized + Clone> IndexMut<bool> for Pair<T> {
    fn index_mut(&mut self, index: bool) -> &mut Self::Output {
        &mut self.val[index as usize]
    }
}
