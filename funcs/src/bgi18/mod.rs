use crate::{Group, DPF, Pair, PRG, Seed, usize_to_bits};
use std::marker::PhantomData;

/// DPF scheme based on [[BGI18]].
///
/// [BGI18]: https://eprint.iacr.org/2018/707.pdf
pub struct BGI18<G: Group> {
    _g: PhantomData<G>,
}

/// A DPF correction word
#[derive(Clone, Debug)]
pub struct CorWord {
    pub seed: Seed,
    pub bits: Pair<bool>,
} 

/// A DPF key
///
/// TODO: Can reduce storage in gen by wrapping cor_words in an Rc
#[derive(Debug)]
pub struct DPFKey<G: Group> {
    pub party: bool,
    pub log_domain: usize,
    pub seed: Seed,
    pub cor_words: Vec<CorWord>,
    pub mask: G,
}

impl<G: Group> BGI18<G> {
    fn gen_cor_word(
        prg: &mut PRG,
        inp_bit: bool,
        bits: &mut Pair<bool>,
        seeds: &mut Pair<Seed>,
        value: Option<G>,
    ) -> (CorWord, Option<G>) {
        let nodes = Pair::new(
            prg.expand_node(seeds[0], true, true),
            prg.expand_node(seeds[1], true, true),
        );

        // `inp_bit` tells us which path to take
        let cw = CorWord {
            seed: nodes[0].seeds[!inp_bit] ^ nodes[1].seeds[!inp_bit],
            bits: Pair::new(
                nodes[0].bits[0] ^ nodes[1].bits[0] ^ inp_bit ^ true,
                nodes[0].bits[1] ^ nodes[1].bits[1] ^ inp_bit,
            ),
        };

        for (i, node) in nodes.iter().enumerate()  {
            // If the previous bit was set, we XOR the correction word to the subsequent node
            match bits[i] {
                true => {
                    seeds[i] = node.seeds[inp_bit] ^ cw.seed;
                    bits[i] = node.bits[inp_bit] ^ cw.bits[inp_bit];
                },
                false => {
                    seeds[i] = node.seeds[inp_bit];
                    bits[i] = node.bits[inp_bit];
                }
            };
        }

        // If this is the final correction word, generate the masking group element
        match value {
            Some(val) => {
                let mask = val - prg.to_group(seeds[0]) + prg.to_group(seeds[1]);
                match bits[1] {
                    true => (cw, Some(-mask)),
                    false => (cw, Some(mask)),
                }
            },
            None => (cw, None),
        }
    }


    fn recursive_eval(
        key: &DPFKey<G>,
        seed: Seed,
        bit: bool,
        level: usize,
        parent: usize,
        out: &mut [G],
        prg: &mut PRG,
    ) {
        if level == key.log_domain {
            // Recover additive group share
            let share = match bit {
                true => prg.to_group::<G>(seed) + key.mask,
                false => prg.to_group(seed),
            };
            out[parent] = match key.party {
                true => -share,
                false => share
            };
            return
        }

        // Evaluate both paths of the tree
        let mut node = prg.expand_node(seed, true, true);

        if bit {
            for path in 0..=1 {
                node.seeds[path] ^= key.cor_words[level].seed;
                node.bits[path] ^= key.cor_words[level].bits[path];
            }
        }

        // Recursive call to the left path
        Self::recursive_eval(
            key,
            node.seeds[0],
            node.bits[0],
            level + 1,
            parent,
            out,
            prg,
        );

        // Recursive call to the right path
        Self::recursive_eval(
            key,
            node.seeds[1],
            node.bits[1],
            level + 1,
            parent + (1 << (key.log_domain - level - 1)),
            out,
            prg
        );
    }
}

impl<G: Group> DPF<G> for BGI18<G> {
    type Key = DPFKey<G>;

    fn gen(
        log_domain: usize,
        point: usize,
        value: G,
        prg: &mut PRG
    ) -> (Self::Key, Self::Key) {
        // Randomly generate root seeds and initialize PRG
        let root_seeds = Pair::new(Seed::rand(), Seed::rand());
        let root_bits = Pair::new(false, true);

        // Iteratively generate codewords for each level of the tree
        let mut seeds = root_seeds;
        let mut bits = root_bits;
        let mut mask = G::zero();
        let cor_words: Vec<CorWord> = usize_to_bits(log_domain, point)
            .iter()
            .enumerate()
            .map(|(i, &inp_bit)| {
                if i == log_domain - 1 {
                    let (cw, m) = Self::gen_cor_word(
                        prg,
                        inp_bit,
                        &mut bits,
                        &mut seeds,
                        Some(value)
                    );
                    mask = m.unwrap();
                    cw
                } else {
                    Self::gen_cor_word(prg, inp_bit, &mut bits, &mut seeds, None).0
                }
            }).collect();

        (
            DPFKey {
                party: false,
                log_domain,
                seed: root_seeds[0],
                cor_words: cor_words.clone(),
                mask: mask.clone(),
            },
            DPFKey {
                party: true,
                log_domain,
                seed: root_seeds[1],
                cor_words,
                mask,
            }
        )
    }

    fn eval(key: &Self::Key, point: &[bool], prg: &mut PRG) -> G {
        debug_assert!(point.len() <= key.log_domain);

        // Initialize state for evaluation
        let mut seed = key.seed;
        let mut bit = key.party;

        // Evaluate each bit of the path
        for i in 0..key.log_domain {
            let mut node = prg.expand_node(seed, !point[i], point[i]);

            if bit {
                node.seeds[point[i]] ^= key.cor_words[i].seed;
                node.bits[point[i]] ^= key.cor_words[i].bits[point[i]];
            }
            seed = node.seeds[point[i]];
            bit = node.bits[point[i]];
        }

        // Recover additive group share
        let share = match bit {
            true => prg.to_group::<G>(seed) + key.mask,
            false => prg.to_group(seed),
        };
        match key.party {
            true => -share,
            false => share
        }
    }


    // TODO: This could take better use of memory + vectorization
    fn eval_full(key: &Self::Key, prg: &mut PRG) -> Vec<G> {
        let mut output = vec![G::zero(); 1 << key.log_domain];
        Self::recursive_eval(
            key,
            key.seed,
            key.party,
            0,
            0,
            &mut output,
            prg,
        );
        output
    }
}
