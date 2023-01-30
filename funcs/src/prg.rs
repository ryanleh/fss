use aes::{Aes128, cipher::{KeyInit, BlockEncrypt}};
use rand::Rng;
use crate::{Group, Pair};

/// AES block size in bytes
const AES_BLOCK_SIZE: usize = 16;

// TODO: For now basic PRG type from the AES crate
// TODO: Not gonna do any fancy AES stuff so we can benchmark later
pub struct PRG {
    aes: Aes128,
    ctr: u128,
}

// TODO: Could reduce online memory usage by having a separate struct here
pub struct Node {
    pub bits: Pair<bool>,
    pub seeds: Pair<Seed>,
}

impl PRG {
    pub fn new() -> PRG {
        // TODO: Using the one-way compression function with a
        // fixed-key AES cipher. Check security of this
        //
        // TODO: Switch to the one given on page 18 here:
        //  https://eprint.iacr.org/2019/074.pdf
        Self {
            aes: Aes128::new(&[0u8; AES_BLOCK_SIZE].into()),
            ctr: 0,
        }
    }

    fn eval(&mut self, out: &mut [u8; AES_BLOCK_SIZE]) {
        // `out` will equal AES(ctr) XOR ctr
        let ctr_bytes = self.ctr.to_le_bytes();
        *out = ctr_bytes;
        self.aes.encrypt_block(out.into());
        out
            .iter_mut()
            .zip(ctr_bytes)
            .for_each(|(e1, e2)| *e1 ^= e2); 
        self.ctr += 1;
    }

    pub fn expand_node(&mut self, mut seed: Seed, left: bool, right: bool) -> Node {
        // TODO: The bits are pulled directly from the seed, we zero them out before evaluating.
        // Check security of this
        let mut out = Node {
            bits: Pair::new((seed[0] & 0x1) == 0, (seed[0] & 0x2) == 0),
            seeds: Pair::new(Seed::zero(), Seed::zero()),
        };
        seed[0] &= 0xFC;

        // Initialize the counter to be the seed 
        self.ctr = seed.into();

        match left {
            true => self.eval(&mut out.seeds[0].0),
            false => self.ctr += 1,
        };

        match right {
            true => self.eval(&mut out.seeds[1].0),
            false => self.ctr += 1,
        };
        
        out
    }

    pub fn to_group<G: Group>(&mut self, seed: Seed) -> G {
        // Initialize the counter to be the seed 
        self.ctr = seed.into();
        G::sample(self)
    }
}

impl rand::RngCore for PRG {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    // TODO: This can be parallelized if it's ever a bottleneck
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        let mut dst_ptr = 0;
        while dst_ptr + AES_BLOCK_SIZE < dst.len() {
            let block = &mut dst[dst_ptr..dst_ptr+AES_BLOCK_SIZE].try_into().unwrap();
            self.eval(block);
            dst_ptr += AES_BLOCK_SIZE;
        }

        let leftover = dst.len() - dst_ptr;
        if leftover != 0 {
            let mut buf = [0u8; AES_BLOCK_SIZE];
            self.eval(&mut buf);
            dst[dst_ptr..].copy_from_slice(&buf[..leftover]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

/// A PRG Seed
#[derive(Copy, Clone, Debug)]
pub struct Seed([u8; AES_BLOCK_SIZE]);

impl Seed {
    fn zero() -> Self {
        Self([0u8; AES_BLOCK_SIZE])
    }

    pub fn rand() -> Self {
        let mut seed = [0u8; AES_BLOCK_SIZE];
        rand::thread_rng().fill(&mut seed);
        Self(seed)
    }
}

impl std::ops::BitXor for Seed {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        let mut out = Self::zero();
        for i in 0..AES_BLOCK_SIZE {
            out.0[i] = self.0[i] ^ rhs.0[i];
        }
        out
    }
}

impl std::ops::BitXorAssign for Seed {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}


impl std::ops::Index<usize> for Seed {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl std::ops::IndexMut<usize> for Seed {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl std::convert::Into<u128> for Seed {
    fn into(self) -> u128 {
        u128::from_le_bytes(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Z256;

    #[test]
    fn prg_consistency() {
        // Check that two different instances of the PRG give the same result on the same seed
        let seed = Seed::rand();
        let mut prg1 = PRG::new();
        let mut prg2 = PRG::new();

        // Do something random with one of the PRGs so they're in a different state
        prg1.expand_node(Seed::rand(), true, true);

        assert_eq!(prg1.to_group::<Z256>(seed), prg2.to_group::<Z256>(seed));
    }
}
