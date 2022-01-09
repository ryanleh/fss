use ark_ff::Field;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use std::{error::Error, marker::PhantomData, rc::Rc, vec::Vec};

use crate::{interval::DIF, Pair, Seed, FSS};

mod data_structures;
pub use data_structures::*;

/// DIF scheme based on [[BGI18]].
///
/// [BGI18]: https://www.iacr.org/archive/eurocrypt2015/90560300/90560300.pdf
pub struct BGI18<F, PRG, S>
where
    F: Field,
    PRG: CryptoRng + RngCore + SeedableRng<Seed = S>,
    S: Seed,
{
    _field: PhantomData<F>,
    _prg: PhantomData<PRG>,
    _seed: PhantomData<S>,
}

impl<F, PRG, S> BGI18<F, PRG, S>
where
    F: Field,
    PRG: CryptoRng + RngCore + SeedableRng<Seed = S>,
    S: Seed,
{
    /// Generates the root of the evaluation tree
    fn gen_root<RNG: CryptoRng + RngCore>(
        bit: bool,
        val: F,
        rng: &mut RNG,
    ) -> (Node<F, S>, Node<F, S>) {
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
}

impl<F, PRG, S> FSS for BGI18<F, PRG, S>
where
    F: Field,
    PRG: CryptoRng + RngCore + SeedableRng<Seed = S>,
    S: Seed,
{
    type Key = Key<F, S>;
    type Description = super::IFDescription<F>;
    type Domain = super::IFDomain;
    type Range = super::IFRange<F>;
    type Share = super::IFRange<F>;

    fn gen<RNG: CryptoRng + RngCore>(
        f: &Self::Description,
        rng: &mut RNG,
    ) -> Result<(Self::Key, Self::Key), Box<dyn Error>> {
        // Parse the function description
        let (log_domain, point, val) = *f;

        // Bit-decompose the input point
        let point = crate::usize_to_bits(log_domain, point)?;

        // Randomly generate the root node of the DIF evaluation tree
        let (p1_root, p2_root) = Self::gen_root(point[0], val, rng);

        // Generate codewords for each level of the tree
        let mut all_codewords = Vec::<Pair<CodeWord<F, S>>>::new();
        all_codewords.reserve_exact(log_domain - 1);

        // Keep track of which node of the tree we're in
        let mut p1_node = IntermediateNode::new(point[0], &p1_root);
        let mut p2_node = IntermediateNode::new(point[0], &p2_root);

        for i in 0..(log_domain - 1) {
            // Use the previous node to sample new masked nodes corresponding to `bit_idx`
            let p1_masked_node = MaskedNode::<PRG, F, S>::sample_masked_node(&p1_node);
            let p2_masked_node = MaskedNode::<PRG, F, S>::sample_masked_node(&p2_node);

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
            rng.fill_bytes(codeword_0_seeds[point[i + 1]].as_mut());
            rng.fill_bytes(codeword_1_seeds[point[i + 1]].as_mut());

            // The seed masks corresponding to `!point` are sampled randomly according to the
            // following contraint: both parties hold the same seed after applying this mask i.e.
            // their XOR is false
            //
            // TODO: Use SIMD here
            rng.fill_bytes(codeword_0_seeds[!point[i + 1]].as_mut());
            codeword_1_seeds[!point[i + 1]]
                .as_mut()
                .iter_mut()
                .zip(codeword_0_seeds[!point[i + 1]].as_ref())
                .zip(p1_masked_node.masked_seeds[!point[i + 1]].as_ref())
                .zip(p2_masked_node.masked_seeds[!point[i + 1]].as_ref())
                .for_each(|(((cs_1, cs_0), p1_s), p2_s)| {
                    *cs_1 = cs_0 ^ p1_s ^ p2_s;
                });

            // The control-bits corresponding to `point` are sampled randomly according to the
            // following contraint: the control-bits of the parties are different i.e. their XOR is
            // true
            codeword_0_control_bits[point[i + 1]] = rng.gen_bool(0.5);
            codeword_1_control_bits[point[i + 1]] = true
                ^ codeword_0_control_bits[point[i + 1]]
                ^ p1_masked_node.masked_control_bits[point[i + 1]]
                ^ p2_masked_node.masked_control_bits[point[i + 1]];

            // The control-bits corresponding to `!point` are sampled randomly according to the
            // following contraint: the control-bits of the parties are the same i.e. their XOR is
            // false
            codeword_0_control_bits[!point[i + 1]] = rng.gen_bool(0.5);
            codeword_1_control_bits[!point[i + 1]] = false
                ^ codeword_0_control_bits[!point[i + 1]]
                ^ p1_masked_node.masked_control_bits[!point[i + 1]]
                ^ p2_masked_node.masked_control_bits[!point[i + 1]];

            // The field-elements corresponding to `point` are sampled randomly according to the
            // following constraint: the difference of the parties' field elements is equal to
            // zero
            //
            // Note that the match statement is necessary since this is a subtractive FSS so the
            // signs of things may change depending on which party selects which codeword.
            codeword_0_elems[point[i + 1]] = F::rand(rng);
            codeword_1_elems[point[i + 1]] = match p1_node.control_bit {
                true => {
                    F::zero() + codeword_0_elems[point[i + 1]]
                        - p1_masked_node.masked_elems[point[i + 1]]
                        + p2_masked_node.masked_elems[point[i + 1]]
                }
                false => {
                    F::zero()
                        + codeword_0_elems[point[i + 1]]
                        + p1_masked_node.masked_elems[point[i + 1]]
                        - p2_masked_node.masked_elems[point[i + 1]]
                }
            };

            // The field-elements corresponding to `!point` are sampled randomly according to the
            // following constraint: the difference of the parties' field elements is equal to `val
            // * point[i + 1]`
            //
            // Note that the match statement is necessary since this is a subtractive FSS so the
            // signs of things may change depending on which party selects which codeword.
            codeword_0_elems[!point[i + 1]] = F::rand(rng);
            // `g := point[i + 1] * val`
            let g = match point[i + 1] {
                true => val,
                false => F::zero(),
            };
            codeword_1_elems[!point[i + 1]] = match p1_node.control_bit {
                true => {
                    g + codeword_0_elems[!point[i + 1]] - p1_masked_node.masked_elems[!point[i + 1]]
                        + p2_masked_node.masked_elems[!point[i + 1]]
                }
                false => {
                    -g + codeword_0_elems[!point[i + 1]]
                        + p1_masked_node.masked_elems[!point[i + 1]]
                        - p2_masked_node.masked_elems[!point[i + 1]]
                }
            };

            // Using the masked nodes and generated codewords, derive the node for the next level
            // of evaluation and save the codewords
            let codewords = Pair::new(
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
            );

            p1_node = IntermediateNode::unmask_node(
                point[i + 1],
                p1_masked_node,
                &codewords[p1_node.control_bit],
                None,
            );
            p2_node = IntermediateNode::unmask_node(
                point[i + 1],
                p2_masked_node,
                &codewords[p2_node.control_bit],
                None,
            );

            all_codewords.push(codewords);
        }
        // Construct and return the resulting keys
        let key_1 = Key {
            log_domain,
            root: p1_root,
            codewords: Rc::new(all_codewords),
        };

        let key_2 = Key {
            log_domain,
            root: p2_root,
            codewords: key_1.codewords.clone(),
        };

        Ok((key_1, key_2))
    }

    fn eval(key: &Self::Key, point: &Self::Domain) -> Result<F, Box<dyn Error>> {
        // Bit-decompose the input point
        let point = crate::usize_to_bits(key.log_domain, *point)?;

        // Iterate through each layer of the tree, using the current node's seed to generate new
        // masked nodes, the current node's control bit to select the correct codeword, and the
        // codeword to unmask the masked node to get the next node in the tree
        let mut node = IntermediateNode::new(point[0], &key.root);
        // At each node in the tree path, the accumulator value will be updated. The final value
        // will be a secret share of `val` or 0.
        let mut accumulator = key.root.elems[point[0]];
        for i in 1..key.log_domain {
            // Use the previous node's seed to sample a masked node corresponding to `bit_idx`
            let masked_node = MaskedNode::<PRG, F, S>::sample_masked_node(&node);

            // Use the previous node's control bit to select the correct codeword
            let codeword = &key.codewords[i - 1][node.control_bit];

            // Combine the masked node and codeword to get the next node and update the accumulator
            node = IntermediateNode::unmask_node(
                point[i],
                masked_node,
                codeword,
                Some(&mut accumulator),
            );
        }
        Ok(accumulator)
    }

    fn decode(shares: (&Self::Share, &Self::Share)) -> Result<Self::Range, Box<dyn Error>> {
        Ok(*shares.0 - shares.1)
    }
}

impl<F, PRG, S> DIF<F> for BGI18<F, PRG, S>
where
    F: Field,
    PRG: CryptoRng + RngCore + SeedableRng<Seed = S>,
    S: Seed,
{
}
