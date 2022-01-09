//! A module implementing various distributed interval function schemes
use ark_ff::Field;

use crate::FSS;

#[cfg(test)]
pub(crate) mod tests;

/// DIF scheme based on [[BGI18]].
///
/// [BGI18]: https://www.iacr.org/archive/eurocrypt2015/90560300/90560300.pdf
pub mod bgi18;

/// The domain of an interval function
type IFDomain = usize;

/// The range of an interval function
type IFRange<F> = F;

/// The description of an interval function: the logarithm of the domain size, a
/// point `x` in that domain, and the evalutaion value of any point `y` where
/// `y < x`
type IFDescription<F> = (usize, usize, F);

/// A distributed interval function (DIF) is a type of FSS scheme for interval functions.
pub trait DIF<F: Field>:
    FSS<Domain = IFDomain, Range = IFRange<F>, Description = IFDescription<F>>
{
}
