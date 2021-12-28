<h1 align="center">Function Secret Sharing</h1>

`fss` contains several Rust libraries for designing and using **functional secret sharing schemes**. 

**WARNING:** This is an academic prototype, and in particular has not received careful code review. These libraries are NOT ready for production use.

## Overview

A funtional secret sharing (FSS) scheme is a cryptographic primitive which enables a party to secret-share a function. In particular, a FSS scheme takes as input a function `f`, and outputs a number of succinct keys which are distributed among parties. These keys enable each party to efficiently generate a secret share of a function evaluation `f(x)` while not revealing any information about `f`.

This library provides Rust crates for a few different types of FSS schemes:

* [`dpf`](dpf): Provides generic implementations of various distributed point functions

## Build guide

The library compiles on the `nightly` toolchain of the Rust compiler (v 1.59+). To install the latest version of Rust, first install `rustup` by following the instructions [here](https://rustup.rs/), or via your platform's package manager. Once `rustup` is installed, install the Rust toolchain by invoking:

```bash
rustup install nightly
```

After that, use `cargo`, the standard Rust build tool, to build the libraries:

```bash
git clone https://github.com/ryanleh/fss.git
cd fss
cargo build --release
```

_Note: The `nightly` toolchain is required since we use the unstable [`min_specialization` feature](https://github.com/rust-lang/rfcs/pull/1210) to lower communication costs. No other unstable features are used._


## Tests

This library comes with comprehensive tests for each of the provided crates. Run the tests with:

```bash
cargo test --all
```

## Benchmarks

This library comes with benchmarks for each of the provided crates. Run the benchmarks with:

```bash
cargo bench
```

## License

This library is licensed under the [MIT License](LICENSE-MIT)
