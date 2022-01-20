use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize as Deserialize, CanonicalSerialize as Serialize, *};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use std::{error::Error, marker::PhantomData, vec::Vec};

use crate::{
    point::DPF,
    tree::{TreeFSS, TreeScheme},
    Pair, Seed,
};

/// DPF scheme based on [[BGI15]].
///
/// [BGI15]: https://www.iacr.org/archive/eurocrypt2015/90560300/90560300.pdf
pub type Bgi15DPF<F, PRG, S> = TreeScheme<F, PRG, S, Bgi15<F, PRG, S>>;

impl<F, PRG, S> DPF<F> for Bgi15DPF<F, PRG, S>
where
    F: Field,
    PRG: CryptoRng + RngCore + SeedableRng<Seed = S>,
    S: Seed,
{
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

/// An intermediate node in the DPF tree during evaluation where we know which seed/control-bit is
/// going to be selected.
///
/// Note this is simply a memory optimization, since we still need to fully evaluate the PRG for
/// correctness
pub struct IntermediateNode<S: Seed> {
    pub seed: S,
    pub control_bit: bool,
}

impl<S: Seed> IntermediateNode<S> {
    /// Construct `Self` from a `Node` and a given bit
    pub fn new(bit: bool, seeds: &Pair<S>, control_bits: &Pair<bool>) -> Self {
        IntermediateNode {
            seed: seeds[bit],
            control_bit: control_bits[bit],
        }
    }
}

pub struct Bgi15<F, PRG, S>
where
    F: Field,
    PRG: CryptoRng + RngCore + SeedableRng<Seed = S>,
    S: Seed,
{
    _field: PhantomData<F>,
    _prg: PhantomData<PRG>,
    _seed: PhantomData<S>,
}

impl<F, PRG, S> TreeFSS<F, PRG, S> for Bgi15<F, PRG, S>
where
    F: Field,
    PRG: CryptoRng + RngCore + SeedableRng<Seed = S>,
    S: Seed,
{
    type Root = Node<S>;
    type Codeword = Pair<CodeWord<S>>;
    type Description = super::PFDescription<F>;
    type Node = Node<S>;
    type EvaluationNode = IntermediateNode<S>;

    fn get_domain_and_point(f: &Self::Description) -> Result<(usize, Vec<bool>), Box<dyn Error>> {
        let log_domain = f.0;
        let x = crate::usize_to_bits(log_domain, f.1)?;
        Ok((log_domain, x))
    }

    fn gen_root<RNG: CryptoRng + RngCore>(
        _: &Self::Description,
        bit: bool,
        rng: &mut RNG,
    ) -> (Self::Root, Self::Root) {
        // Sample party 1's initial 0/1 seeds and control bits.
        let mut p1_seeds = Pair::<S>::default();
        rng.fill_bytes(p1_seeds[0].as_mut());
        rng.fill_bytes(p1_seeds[1].as_mut());

        let mut p1_control_bits = Pair::<bool>::default();
        p1_control_bits[0] = rng.gen_bool(0.5);
        p1_control_bits[1] = rng.gen_bool(0.5);

        // Sample party 2's initial seeds and control bits. The seed for the bit corresponding to
        // `!bit` will be the same as party 1, the control bit for `bit` will be different from
        // party 1, and the control bit for `!bit` will be the same as party 1.
        let mut p2_seeds = Pair::<S>::default();
        rng.fill_bytes(p2_seeds[bit].as_mut());
        p2_seeds[!bit] = p1_seeds[!bit];

        let mut p2_control_bits = Pair::<bool>::default();
        p2_control_bits[bit] = !p1_control_bits[bit];
        p2_control_bits[!bit] = p1_control_bits[!bit];

        (
            Node {
                seeds: p1_seeds,
                control_bits: p1_control_bits,
            },
            Node {
                seeds: p2_seeds,
                control_bits: p2_control_bits,
            },
        )
    }

    fn evaluate_root(bit: bool, root: &Self::Root) -> (Self::EvaluationNode, Option<F>) {
        (
            IntermediateNode::new(bit, &root.seeds, &root.control_bits),
            None,
        )
    }

    fn sample_masked_level(node: &Self::EvaluationNode) -> Self::Node {
        let mut prg = PRG::from_seed(node.seed);

        // Sample masked seeds.
        let mut masked_seeds = Pair::<S>::default();
        prg.fill_bytes(masked_seeds[0].as_mut());
        prg.fill_bytes(masked_seeds[1].as_mut());

        // Sample masked control-bits
        let mut masked_control_bits = Pair::<bool>::default();
        masked_control_bits[0] = prg.gen_bool(0.5);
        masked_control_bits[1] = prg.gen_bool(0.5);

        Self::Node {
            seeds: masked_seeds,
            control_bits: masked_control_bits,
        }
    }

    fn compute_codeword<RNG: CryptoRng + RngCore>(
        _: &Self::Description,
        bit: bool,
        _: &Self::EvaluationNode,
        p1_masked_node: &Self::Node,
        p2_masked_node: &Self::Node,
        rng: &mut RNG,
    ) -> Self::Codeword {
        // For each level of the tree, there are two `CodeWords`, each corresponding to the
        // current control bit. Each `CodeWord` contains masks to apply to the current
        // `MaskedNode` in order to get the next `Node`.
        //
        // These masks are designed such that, if the parties are evaluating the path
        // corresponding to `point`, then the subsequent `Node` will be randomly sampled.
        // However, if the path ever diverges from `point`, then these masks will produce an
        // identical `Node` for both parties.
        let mut codeword_0_seeds = Pair::<S>::default();
        let mut codeword_0_control_bits = Pair::<bool>::default();
        let mut codeword_1_seeds = Pair::<S>::default();
        let mut codeword_1_control_bits = Pair::<bool>::default();

        // The seed masks corresponding to `point` are sampled randomly
        rng.fill_bytes(codeword_0_seeds[bit].as_mut());
        rng.fill_bytes(codeword_1_seeds[bit].as_mut());

        // The seed masks corresponding to `!point` are sampled randomly according to the
        // following contraint: both parties hold the same seed after applying this mask i.e.
        // their XOR is false
        //
        // TODO: Use SIMD here
        rng.fill_bytes(codeword_0_seeds[!bit].as_mut());
        codeword_1_seeds[!bit]
            .as_mut()
            .iter_mut()
            .zip(codeword_0_seeds[!bit].as_ref())
            .zip(p1_masked_node.seeds[!bit].as_ref())
            .zip(p2_masked_node.seeds[!bit].as_ref())
            .for_each(|(((cs_1, cs_0), p1_s), p2_s)| {
                *cs_1 = cs_0 ^ p1_s ^ p2_s;
            });

        // The control-bits corresponding to `point` are sampled randomly according to the
        // following contraint: the control-bits of the parties are different i.e. their XOR is
        // true
        codeword_0_control_bits[bit] = rng.gen_bool(0.5);
        codeword_1_control_bits[bit] = true
            ^ codeword_0_control_bits[bit]
            ^ p1_masked_node.control_bits[bit]
            ^ p2_masked_node.control_bits[bit];

        // The control-bits corresponding to `!point` are sampled randomly according to the
        // following contraint: the control-bits of the parties are the same i.e. their XOR is
        // false
        codeword_0_control_bits[!bit] = rng.gen_bool(0.5);
        codeword_1_control_bits[!bit] = false
            ^ codeword_0_control_bits[!bit]
            ^ p1_masked_node.control_bits[!bit]
            ^ p2_masked_node.control_bits[!bit];

        // Using the masked nodes and generated codewords, derive the node for the next level
        // of evaluation and save the codewords
        Pair::new(
            CodeWord {
                seeds: codeword_0_seeds,
                control_bits: codeword_0_control_bits,
            },
            CodeWord {
                seeds: codeword_1_seeds,
                control_bits: codeword_1_control_bits,
            },
        )
    }

    fn compute_next_level(
        bit: bool,
        node: &Self::EvaluationNode,
        mut masked_node: Self::Node,
        codewords: &Self::Codeword,
        _: Option<&mut F>,
    ) -> Self::EvaluationNode {
        // Select the correct codeword
        let codeword = codewords[node.control_bit];

        // XOR `masked_node` with `codeword` in-place
        masked_node.seeds[bit]
            .as_mut()
            .iter_mut()
            .zip(codeword.seeds[bit].as_ref())
            .for_each(|(s, cs)| *s ^= cs);
        masked_node.control_bits[bit] ^= codeword.control_bits[bit];

        IntermediateNode {
            seed: masked_node.seeds[bit],
            control_bit: masked_node.control_bits[bit],
        }
    }

    #[inline]
    fn compute_output_elem(node: &Self::EvaluationNode) -> Option<F> {
        // Using the PRG seed, sample a random field element
        Some(F::rand(&mut PRG::from_seed(node.seed)))
    }

    #[inline]
    fn compute_mask(
        f: &Self::Description,
        p1_output_elem: &Option<F>,
        p2_output_elem: &Option<F>,
    ) -> Result<Option<F>, Box<dyn Error>> {
        let (_, _, val) = *f;
        let p1_elem = p1_output_elem.ok_or("Gen(): Output element is None")?;
        let p2_elem = p2_output_elem.ok_or("Gen(): Output element is None")?;
        // Output a mask s.t. both parties hold additive secret shares of `val`
        match p1_elem == p2_elem {
            true => {
                // If the elements are the same than `mask = 0` which breaks security
                Err("Parties final PRG output is the same")?
            }
            false => Ok(Some(
                ((p1_elem - p2_elem)
                    .inverse()
                    .ok_or("Parties shares sum to zero")?)
                    * val,
            )),
        }
    }
}
