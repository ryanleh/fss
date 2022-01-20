//! A module implementing various distributed point function schemes
use ark_ff::Field;

use crate::FSS;

#[cfg(test)]
pub(crate) mod tests;

/// DPF scheme based on [[BGI15]].
///
/// [BGI15]: https://www.iacr.org/archive/eurocrypt2015/90560300/90560300.pdf
pub mod bgi15;

/// The domain of a point function
type PFDomain = usize;

/// The range of a point function
type PFRange<F> = F;

/// The description of a point function: the logarithm of the domain size, a
/// point in that domain, and the value of that point.
type PFDescription<F> = (usize, usize, F);

/// A distributed point function (DPF) is a type of FSS scheme for point functions.
pub trait DPF<F: Field>:
    FSS<Domain = PFDomain, Range = PFRange<F>, Description = PFDescription<F>>
{
}
