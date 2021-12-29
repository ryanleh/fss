use ark_ff::Field;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use std::{error::Error, marker::PhantomData, rc::Rc, vec::Vec};

use super::DPF;

mod data_structures;
pub use data_structures::*;

/// DPF scheme based on [[BGI18]].
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
    /// Converts a `usize` to a vector of bools in little endian format
    #[inline]
    fn usize_to_bits(log_domain: usize, val: usize) -> Result<Vec<bool>, Box<dyn Error>> {
        // Ensure that the point is valid in the given domain
        if val >= (1 << log_domain) {
            return Err("Input point is not contained in provided domain")?;
        }

        let mut bits = Vec::new();
        bits.reserve(log_domain - 1);

        // Compute the bit-decomposition
        let bytes = val.to_le_bytes();
        for i in 0..log_domain {
            let mask = 1 << (i % 8);
            let bit = mask & bytes[(i / 8) as usize];
            bits.push(bit != 0);
        }
        Ok(bits)
    }

    /// Generates the root of the evaluation tree
    fn gen_root<RNG: CryptoRng + RngCore>(bit: bool, rng: &mut RNG) -> (DPFNode<S>, DPFNode<S>) {
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
            DPFNode {
                seeds: p1_seeds,
                control_bits: p1_control_bits,
            },
            DPFNode {
                seeds: p2_seeds,
                control_bits: p2_control_bits,
            },
        )
    }
}

impl<F, PRG, S> DPF<F> for BGI18<F, PRG, S>
where
    F: Field,
    PRG: CryptoRng + RngCore + SeedableRng<Seed = S>,
    S: Seed,
{
    type Key = Key<F, S>;

    fn gen<RNG: CryptoRng + RngCore>(
        log_domain: usize,
        point: usize,
        val: F,
        rng: &mut RNG,
    ) -> Result<(Self::Key, Self::Key), Box<dyn Error>> {
        // Bit-decompose the input point
        let point = Self::usize_to_bits(log_domain, point)?;

        // Randomly generate the root node of the DPF evaluation tree
        let (p1_root, p2_root) = Self::gen_root(point[0], rng);

        // Generate codewords for each level of the tree
        let mut all_codewords = Vec::<Pair<CodeWord<S>>>::new();
        all_codewords.reserve_exact(log_domain - 1);

        // Keep track of which node of the tree we're in
        let mut p1_node = IntermediateDPFNode::new(point[0], &p1_root);
        let mut p2_node = IntermediateDPFNode::new(point[0], &p2_root);

        for i in 0..(log_domain - 1) {
            // Use the previous node to sample new masked nodes corresponding to `bit_idx`
            let p1_masked_node = MaskedDPFNode::<PRG, S>::sample_masked_node(&p1_node);
            let p2_masked_node = MaskedDPFNode::<PRG, S>::sample_masked_node(&p2_node);

            // For each level of the tree, there are two `CodeWords`, each corresponding to the
            // current control bit. Each `CodeWord` contains masks to apply to the current
            // `MaskedDPFNode` in order to get the next `DPFNode`.
            //
            // These masks are designed such that, if the parties are evaluating the path
            // corresponding to `point`, then the subsequent `DPFNode` will be randomly sampled.
            // However, if the path ever diverges from `point`, then these masks will produce an
            // identical `DPFNode` for both parties.
            let mut codeword_0_seeds = Pair::<S>::default();
            let mut codeword_0_control_bits = Pair::<bool>::default();
            let mut codeword_1_seeds = Pair::<S>::default();
            let mut codeword_1_control_bits = Pair::<bool>::default();

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

            // Using the masked nodes and generated codewords, derive the node for the next level
            // of evaluation and save the codewords
            let codewords = Pair::new(
                CodeWord {
                    seeds: codeword_0_seeds,
                    control_bits: codeword_0_control_bits,
                },
                CodeWord {
                    seeds: codeword_1_seeds,
                    control_bits: codeword_1_control_bits,
                },
            );

            p1_node = IntermediateDPFNode::unmask_node(
                point[i + 1],
                p1_masked_node,
                &codewords[p1_node.control_bit],
            );
            p2_node = IntermediateDPFNode::unmask_node(
                point[i + 1],
                p2_masked_node,
                &codewords[p2_node.control_bit],
            );

            all_codewords.push(codewords);
        }
        // Using the final PRG seeds, sample random field elements and output a mask s.t. both
        // parties hold additive secret shares of `val`
        let p1_elem = F::rand(&mut PRG::from_seed(p1_node.seed));
        let p2_elem = F::rand(&mut PRG::from_seed(p2_node.seed));

        let mask: F;
        // If the elements are the same than `mask = 0` which breaks security
        if p1_elem == p2_elem {
            return Err("Parties final PRG output is the same")?;
        } else {
            mask = ((p1_elem - p2_elem)
                .inverse()
                .ok_or("Parties shares sum to zero")?)
                * val;
        };

        // Construct and return the resulting keys
        let key_1 = Key {
            log_domain,
            root: p1_root,
            codewords: Rc::new(all_codewords),
            mask,
        };

        let key_2 = Key {
            log_domain,
            root: p2_root,
            codewords: key_1.codewords.clone(),
            mask,
        };

        Ok((key_1, key_2))
    }

    fn eval(key: &Self::Key, point: usize) -> Result<F, Box<dyn Error>> {
        // Bit-decompose the input point
        let point = Self::usize_to_bits(key.log_domain, point)?;

        // Iterate through each layer of the tree, using the current node's seed to generate new
        // masked nodes, the current node's control bit to select the correct codeword, and the
        // codeword to unmask the masked node to get the next node in the tree
        let mut node = IntermediateDPFNode::new(point[0], &key.root);
        for i in 1..key.log_domain {
            // Use the previous node's seed to sample a masked node corresponding to `bit_idx`
            let masked_node = MaskedDPFNode::<PRG, S>::sample_masked_node(&node);

            // Use the previous node's control bit to select the correct codeword
            let codeword = &key.codewords[i - 1][node.control_bit];

            // Combine the masked node and codeword to get the next node
            node = IntermediateDPFNode::unmask_node(point[i], masked_node, codeword);
        }
        // Use the final PRG seed to generate the masked field element
        let elem = F::rand(&mut PRG::from_seed(node.seed));
        Ok(elem * key.mask)
    }
}
