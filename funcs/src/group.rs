use crypto_bigint::{Encoding, U256, Wrapping};
use num_traits::Zero;
use std::ops::{Add, Neg, Sub};

/// TODO
pub trait Group:
    Sized
    + Clone
    + Copy
    + std::fmt::Debug
    + Zero
    + Add<Self, Output = Self>
    + Sub<Self, Output = Self>
    + Neg<Output = Self>
    + Eq
{
    /// Randomly sample a group element
    fn sample<PRG: rand::Rng>(prg: &mut PRG) -> Self;
}


/// A group represented by the integers modulo 2^256. Since this modulus is an exact multiple of
/// the limb size, reductions are implicitly performed.
///
/// Note this is _not_ GF(2^256) as elements are represented via standard integers
#[derive(Copy, Clone, Debug)]
pub struct Z256(Wrapping<U256>);

impl Z256 {
    fn new(bytes: [u8; 32]) -> Self {
        Self(Wrapping(U256::from_le_bytes(bytes)))
    }
    
    fn inner(self) -> [u8; 32] {
        self.0.0.to_le_bytes()
    }
}

impl Group for Z256 {
    fn sample<PRG: rand::Rng>(prg: &mut PRG) -> Self {
        let mut repr = [0u8; 32];
        prg.fill_bytes(&mut repr);
        Self(Wrapping(U256::from_le_bytes(repr)))
    }

}

impl Zero for Z256 {
    fn zero() -> Self {
        Self(Wrapping(U256::ZERO))
    }

    fn is_zero(&self) -> bool {
        self.0.0 == U256::ZERO
    }
}

impl Add for Z256 {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self.0 += rhs.0;
        self
    }
}

impl Sub for Z256 {
    type Output = Self;

    fn sub(mut self, rhs: Self) -> Self::Output {
        self.0 -= rhs.0;
        self
    }
}

impl Neg for Z256 {
    type Output = Self;

    fn neg(mut self) -> Self::Output {
        self.0 = Wrapping(U256::ZERO) - self.0;
        self
    }
}

impl PartialEq for Z256 {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for Z256 {}


#[cfg(test)]
mod tests {
    use crate::{Group, Z256};
    use crypto_bigint::{Encoding, U256, Wrapping};
    use std::ops::Neg;

    #[test]
    fn group_arithmetic() {
        // Initialize PRG
        let mut prg = rand::thread_rng();

        for _ in 0..1000 {
            // Sample two random elements in Zp
            let e1 = Z256::sample(&mut prg);
            let e2 = Z256::sample(&mut prg);

            let e1_repr = Wrapping(U256::from_le_bytes(e1.inner()));
            let e2_repr = Wrapping(U256::from_le_bytes(e2.inner()));

            // Add
            assert_eq!(
                e1_repr + e2_repr,
                Wrapping(U256::from_le_bytes((e1 + e2).inner()))
            );

            // Sub
            assert_eq!(
                e1_repr - e2_repr,
                Wrapping(U256::from_le_bytes((e1 - e2).inner()))
            );

            assert_eq!(
                e2_repr - e1_repr,
                Wrapping(U256::from_le_bytes((e2 - e1).inner()))
            );

            // Neg
            assert_eq!(
                e1_repr - e2_repr,
                Wrapping(U256::from_le_bytes((e1 + e2.neg()).inner()))
            );
            
            assert_eq!(
                e2_repr - e1_repr,
                Wrapping(U256::from_le_bytes((e1.neg() + e2).inner()))
            );
        }
    }
}
