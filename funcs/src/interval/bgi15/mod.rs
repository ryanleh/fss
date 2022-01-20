use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize as Deserialize, CanonicalSerialize as Serialize, *};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use std::{error::Error, marker::PhantomData, vec::Vec};

use crate::{
    interval::DIF,
    point::bgi15::IntermediateNode,
    tree::{TreeFSS, TreeScheme},
    Pair, Seed,
};

/// DIF scheme based on [[BGI15]].
///
/// [BGI15]: https://www.iacr.org/archive/eurocrypt2015/90560300/90560300.pdf
pub type Bgi15DIF<F, PRG, S> = TreeScheme<F, PRG, S, Bgi15<F, PRG, S>>;

impl<F, PRG, S> DIF<F> for Bgi15DIF<F, PRG, S>
where
    F: Field,
    PRG: CryptoRng + RngCore + SeedableRng<Seed = S>,
    S: Seed,
{
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
    type Root = Node<F, S>;
    type Codeword = Pair<CodeWord<F, S>>;
    type Description = super::IFDescription<F>;
    type Node = Node<F, S>;
    type EvaluationNode = IntermediateNode<S>;

    fn get_domain_and_point(f: &Self::Description) -> Result<(usize, Vec<bool>), Box<dyn Error>> {
        let log_domain = f.0;
        let x = crate::usize_to_bits(log_domain, f.1)?;
        Ok((log_domain, x))
    }

    fn gen_root<RNG: CryptoRng + RngCore>(
        f: &Self::Description,
        bit: bool,
        rng: &mut RNG,
    ) -> (Self::Root, Self::Root) {
        let (_, _, val) = *f;

        // Sample party 1's initial 0/1 seeds, control bits, and field elements.
        let mut p1_seeds = Pair::<S>::default();
        rng.fill_bytes(p1_seeds[0].as_mut());
        rng.fill_bytes(p1_seeds[1].as_mut());

        let mut p1_control_bits = Pair::<bool>::default();
        p1_control_bits[0] = rng.gen_bool(0.5);
        p1_control_bits[1] = rng.gen_bool(0.5);

        let mut p1_elems = Pair::<F>::default();
        p1_elems[0] = F::rand(rng);
        p1_elems[1] = F::rand(rng);

        // Sample party 2's initial seeds, control bits, and field elements. The seed for the bit
        // corresponding to `!bit` will be the same as party 1, the control bit for `bit` will be
        // different from party 1, the control bit for `!bit` will be the same as party 1, the
        // field element for the bit corresponding to `bit` will be secret shares of 0, and the
        // field elements for `!bit` will be secret shares of `val * bit`.
        let mut p2_seeds = Pair::<S>::default();
        rng.fill_bytes(p2_seeds[bit].as_mut());
        p2_seeds[!bit] = p1_seeds[!bit];

        let mut p2_control_bits = Pair::<bool>::default();
        p2_control_bits[bit] = !p1_control_bits[bit];
        p2_control_bits[!bit] = p1_control_bits[!bit];

        let mut p2_elems = Pair::<F>::default();
        p2_elems[bit] = p1_elems[bit];
        p2_elems[!bit] = match bit {
            true => p1_elems[!bit] - val,
            false => p1_elems[!bit],
        };

        (
            Node {
                seeds: p1_seeds,
                control_bits: p1_control_bits,
                elems: p1_elems,
            },
            Node {
                seeds: p2_seeds,
                control_bits: p2_control_bits,
                elems: p2_elems,
            },
        )
    }

    fn evaluate_root(bit: bool, root: &Self::Root) -> (Self::EvaluationNode, Option<F>) {
        // We don't use the `elem` field to help generate future levels so it's not part of the
        // `EvaluationNode`
        (
            IntermediateNode::new(bit, &root.seeds, &root.control_bits),
            Some(root.elems[bit]),
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

        // Sample masked field elems
        let mut masked_elems = Pair::<F>::default();
        masked_elems[0] = F::rand(&mut prg);
        masked_elems[1] = F::rand(&mut prg);

        Self::Node {
            seeds: masked_seeds,
            control_bits: masked_control_bits,
            elems: masked_elems,
        }
    }

    fn compute_codeword<RNG: CryptoRng + RngCore>(
        f: &Self::Description,
        bit: bool,
        p1_node: &Self::EvaluationNode,
        p1_masked_node: &Self::Node,
        p2_masked_node: &Self::Node,
        rng: &mut RNG,
    ) -> Self::Codeword {
        let (_, _, val) = *f;

        // For each level of the tree, there are two `CodeWords`, each corresponding to the
        // current control bit. Each `CodeWord` contains masks to apply to the current
        // `MaskedNode` in order to get the next `Node`.
        //
        // These masks are designed such that, if the parties are evaluating the path
        // at or to the right of `point`, then the difference of the resulting field elements
        // will be zero. However, if the path is ever to the left of `point` then the
        // difference of the resulting field elements will be `val`.
        let mut codeword_0_seeds = Pair::<S>::default();
        let mut codeword_0_control_bits = Pair::<bool>::default();
        let mut codeword_0_elems = Pair::<F>::default();
        let mut codeword_1_seeds = Pair::<S>::default();
        let mut codeword_1_control_bits = Pair::<bool>::default();
        let mut codeword_1_elems = Pair::<F>::default();

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

        // The field-elements corresponding to `point` are sampled randomly according to the
        // following constraint: the difference of the parties' field elements is equal to
        // zero
        //
        // Note that the match statement is necessary since this is a subtractive FSS so the
        // signs of things may change depending on which party selects which codeword.
        codeword_0_elems[bit] = F::rand(rng);
        codeword_1_elems[bit] = match p1_node.control_bit {
            true => {
                F::zero() + codeword_0_elems[bit] - p1_masked_node.elems[bit]
                    + p2_masked_node.elems[bit]
            }
            false => {
                F::zero() + codeword_0_elems[bit] + p1_masked_node.elems[bit]
                    - p2_masked_node.elems[bit]
            }
        };

        // The field-elements corresponding to `!point` are sampled randomly according to the
        // following constraint: the difference of the parties' field elements is equal to `val
        // * bit`
        //
        // Note that the match statement is necessary since this is a subtractive FSS so the
        // signs of things may change depending on which party selects which codeword.
        codeword_0_elems[!bit] = F::rand(rng);
        // `g := bit * val`
        let g = match bit {
            true => val,
            false => F::zero(),
        };
        codeword_1_elems[!bit] = match p1_node.control_bit {
            true => {
                g + codeword_0_elems[!bit] - p1_masked_node.elems[!bit] + p2_masked_node.elems[!bit]
            }
            false => {
                -g + codeword_0_elems[!bit] + p1_masked_node.elems[!bit]
                    - p2_masked_node.elems[!bit]
            }
        };

        // Using the masked nodes and generated codewords, derive the node for the next level
        // of evaluation and save the codewords
        Pair::new(
            CodeWord {
                seeds: codeword_0_seeds,
                control_bits: codeword_0_control_bits,
                elems: codeword_0_elems,
            },
            CodeWord {
                seeds: codeword_1_seeds,
                control_bits: codeword_1_control_bits,
                elems: codeword_1_elems,
            },
        )
    }

    fn compute_next_level(
        bit: bool,
        node: &Self::EvaluationNode,
        mut masked_node: Self::Node,
        codewords: &Self::Codeword,
        accumulator: Option<&mut F>,
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

        // If an accumulator is provided, update it
        if let Some(acc) = accumulator {
            *acc += masked_node.elems[bit] + codeword.elems[bit];
        }
        IntermediateNode {
            seed: masked_node.seeds[bit],
            control_bit: masked_node.control_bits[bit],
        }
    }

    #[inline]
    fn compute_output_elem(_: &Self::EvaluationNode) -> Option<F> {
        None
    }

    #[inline]
    fn compute_mask(
        _: &Self::Description,
        _: &Option<F>,
        _: &Option<F>,
    ) -> Result<Option<F>, Box<dyn Error>> {
        Ok(None)
    }
}
