//! A module providing traits for 2-party FSS schemes following the binary-tree-based PRG approach
//! outlined in [[BGI18]].
//!
//! [BGI18]: https://www.iacr.org/archive/eurocrypt2015/90560300/90560300.pdf
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize as Deserialize, CanonicalSerialize as Serialize, *};
use rand::{CryptoRng, RngCore, SeedableRng};
use std::{error::Error, marker::PhantomData, rc::Rc, vec::Vec};

use crate::{Seed, FSS};

/// An interface for the 2-party FSS scheme following the binary-tree-based PRG approach
/// outlined in [[BGI18]].
///
/// [BGI18]: https://www.iacr.org/archive/eurocrypt2015/90560300/90560300.pdf
pub trait TreeFSS<F, PRG, S>
where
    F: Field,
    PRG: CryptoRng + RngCore + SeedableRng<Seed = S>,
    S: Seed,
{
    /// Description of the underlying function being secret-shared
    type Description;

    /// The root node of the tree. This can contain more information than other nodes in the tree.
    type Root: Serialize + Deserialize;

    /// A node in the tree
    type Node;

    /// A 'hint' given at each level of the tree to ensure correctness of the output
    type Codeword: Serialize + Deserialize;

    /// A node in the tree when evaluating and the exact path being traversed is known. This allows
    /// some additional memory optimizations by not storing information that won't be used.
    type EvaluationNode;

    /// Outputs the log of the domain size and the big-endian bit decomposition of the path in
    /// the tree being evaluated.
    fn get_domain_and_point(f: &Self::Description) -> Result<(usize, Vec<bool>), Box<dyn Error>>;

    /// Generates the root nodes for each party
    fn gen_root<RNG: CryptoRng + RngCore>(
        f: &Self::Description,
        bit: bool,
        rng: &mut RNG,
    ) -> (Self::Root, Self::Root);

    /// Evaluates the root node at the provided bit and returns an `EvaluationNode`
    fn evaluate_root(bit: bool, root: &Self::Root) -> (Self::EvaluationNode, Option<F>);

    /// Using an `EvaluationNode`, sample the corresponding masked node the tree.
    fn sample_masked_level(node: &Self::EvaluationNode) -> Self::Node;

    /// Compute the codeword for the provided masked node
    fn compute_codeword<RNG: CryptoRng + RngCore>(
        f: &Self::Description,
        bit: bool,
        p1_node: &Self::EvaluationNode,
        p1_masked_node: &Self::Node,
        p2_masked_node: &Self::Node,
        rng: &mut RNG,
    ) -> Self::Codeword;

    /// Combine a masked node and codeword to get the next node in the tree
    fn compute_next_level(
        bit: bool,
        node: &Self::EvaluationNode,
        masked_node: Self::Node,
        codeword: &Self::Codeword,
        accumulator: Option<&mut F>,
    ) -> Self::EvaluationNode;

    /// Sample a field element from a tree leaf
    fn compute_output_elem(node: &Self::EvaluationNode) -> Option<F>;

    /// Compute a mask for the output field elements
    fn compute_mask(
        f: &Self::Description,
        p1_output_elem: &Option<F>,
        p2_output_elem: &Option<F>,
    ) -> Result<Option<F>, Box<dyn Error>>;
}

/// An `FSS` key for `TreeFSS` schemes
#[derive(Clone, Serialize, Deserialize)]
pub struct TreeKey<F, PRG, S, T>
where
    F: Field,
    PRG: CryptoRng + RngCore + SeedableRng<Seed = S>,
    S: Seed,
    T: TreeFSS<F, PRG, S>,
{
    pub log_domain: usize,
    pub root: T::Root,
    pub codewords: Rc<Vec<T::Codeword>>,
    pub mask: Option<F>,
}

/// Wrapper struct that implements `FSS` on any type that implements `TreeFSS`.
///
/// TODO: Explore replacing this with a macro
pub struct TreeScheme<F, PRG, S, T>
where
    F: Field,
    PRG: CryptoRng + RngCore + SeedableRng<Seed = S>,
    S: Seed,
    T: TreeFSS<F, PRG, S>,
{
    _f: PhantomData<F>,
    _prg: PhantomData<PRG>,
    _s: PhantomData<S>,
    _t: PhantomData<T>,
}

impl<F, PRG, S, T> FSS for TreeScheme<F, PRG, S, T>
where
    F: Field,
    PRG: CryptoRng + RngCore + SeedableRng<Seed = S>,
    S: Seed,
    T: TreeFSS<F, PRG, S>,
{
    type Key = TreeKey<F, PRG, S, T>;
    type Description = T::Description;
    type Domain = usize;
    type Range = F;
    type Share = F;

    fn gen<RNG: CryptoRng + RngCore>(
        f: &Self::Description,
        rng: &mut RNG,
    ) -> Result<(Self::Key, Self::Key), Box<dyn Error>> {
        // Get the domain size and bit-decomposition of the point from the function description
        let (log_domain, point) = T::get_domain_and_point(f)?;

        // Randomly generate the root node of the evaluation tree
        let (p1_root, p2_root) = T::gen_root(f, point[0], rng);

        // Generate codewords for each level of the tree
        let mut all_codewords = Vec::<T::Codeword>::new();
        all_codewords.reserve_exact(log_domain - 1);

        // Begin evaluating the tree defined by the root along `point`
        let (mut p1_node, _) = T::evaluate_root(point[0], &p1_root);
        let (mut p2_node, _) = T::evaluate_root(point[0], &p2_root);

        for i in 0..(log_domain - 1) {
            // Use the seed from the current `EvaluationNode` to sample the next level of the tree
            let p1_masked_node = T::sample_masked_level(&p1_node);
            let p2_masked_node = T::sample_masked_level(&p2_node);

            // Calculate the codeword for this level of the tree
            let codewords = T::compute_codeword(
                &f,
                point[i + 1],
                &p1_node,
                &p1_masked_node,
                &p2_masked_node,
                rng,
            );

            // Use the codewords to compute the nodes for the next level of the tree
            p1_node =
                T::compute_next_level(point[i + 1], &p1_node, p1_masked_node, &codewords, None);

            p2_node =
                T::compute_next_level(point[i + 1], &p2_node, p2_masked_node, &codewords, None);

            all_codewords.push(codewords);
        }

        // TODO: Optionally compute final field elem
        let p1_elem = T::compute_output_elem(&p1_node);
        let p2_elem = T::compute_output_elem(&p2_node);
        let mask = T::compute_mask(f, &p1_elem, &p2_elem)?;

        // Construct and return the resulting keys
        let key_1 = Self::Key {
            log_domain,
            root: p1_root,
            codewords: Rc::new(all_codewords),
            mask,
        };

        let key_2 = Self::Key {
            log_domain,
            root: p2_root,
            codewords: key_1.codewords.clone(),
            mask,
        };

        Ok((key_1, key_2))
    }

    fn eval(key: &Self::Key, point: &Self::Domain) -> Result<F, Box<dyn Error>> {
        // Bit-decompose the input point
        let point = crate::usize_to_bits(key.log_domain, *point)?;

        // Iterate through each layer of the tree, using the current node to generate new
        // masked nodes and select the correct codeword, and the codeword to unmask the
        // masked node to get the next node in the tree.
        //
        // At each node in the tree path, the accumulator value will be updated. The final value
        // will be a secret share of `val` or 0.
        let (mut node, mut accumulator) = T::evaluate_root(point[0], &key.root);
        for i in 1..key.log_domain {
            // Use the seed from the current `EvaluationNode` to sample the next level of the tree
            let masked_node = T::sample_masked_level(&node);

            // Combine the masked node and codeword to get the next node and update the accumulator
            node = T::compute_next_level(
                point[i],
                &node,
                masked_node,
                &key.codewords[i - 1],
                accumulator.as_mut(),
            );
        }
        if let Some(mask) = key.mask {
            // TODO
            let elem = T::compute_output_elem(&node).unwrap();
            Ok(elem * mask)
        } else if let Some(accum) = accumulator {
            Ok(accum)
        } else {
            unreachable!()
        }
    }

    fn decode(shares: (&Self::Share, &Self::Share)) -> Result<Self::Range, Box<dyn Error>> {
        Ok(*shares.0 - shares.1)
    }
}
