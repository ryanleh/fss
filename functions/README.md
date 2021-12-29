<h1 align="center">fss-functions</h1>

This crate provides traits and implementations for function secret sharing.

Currently the following functions are supported:

### Point functions

A point function `f_{x, y}` is a function which evaluates to `y` on input `x`, and 0 everywhere else in it's domain. We provide implementations of the following point functions:

* [[BGI18]][bgi18]: the domain is `D: {0, 1}^n` and the range `R` is some field `F`

### Interval functions

An interval function `f_{x, y}` is a function which evaluates to `y` on input `a` where `a < x`, and 0 everywhere else in it's domain. We provide implementations of the following interval functions:

* [[BGI18]][bgi18]: the domain is `D: {0, 1}^n` and the range `R` is some field `F`. _Note that this scheme also supports the range `R` being equal to any abelian group `G`, but we have not implemented this since the library we use for algebraic abstractions does not provide a trait for abelian groups._


## Reference papers

[bgi18]: https://www.iacr.org/archive/eurocrypt2015/90560300/90560300.pdf

[Function Secret Sharing][bgi18]\
Elette Boyle, Niv Gilboa, and Yuval Ishai\
Eurocrypt 2015
