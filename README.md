# Hash-Based Signatures - Python Bindings

This repository provides Python bindings for hash-based signature schemes using tweakable hash functions and incomparable encodings.

⚠️ **WARNING**: This is a prototype implementation and has not been audited. Do not use in production!

## Features

- **Python bindings** for hash-based signature schemes
- **SHA3 and Poseidon2** signature schemes
- **Epoch-based signing** with automatic key preparation
- **Serialization** of keys and signatures
- **Cross-platform** support (Linux, macOS, Windows)

## Quick Start

### Installation

```bash
# Install from source
git clone https://github.com/blockblaz/hashsig-py
cd hashsig-py
pip install maturin
maturin develop
```

### Basic Usage

```python
import hashsig_py

# Create a signature scheme
scheme = hashsig_py.HashSigSHA3()

# Generate keys
public_key, secret_key = scheme.key_gen()

# Sign a message
epoch = 100
message = b"Hello, hash-based signatures!"
signature = scheme.sign(secret_key, epoch, message)

# Verify signature
is_valid = scheme.verify(public_key, epoch, message, signature)
print(f"Signature valid: {is_valid}")
```

### Examples

Run the provided examples:

```bash
python test_basic.py      # Comprehensive functionality tests
python simple_example.py  # Simple usage examples
```

## Requirements

- **Rust**: >= 1.87
- **Python**: >= 3.8
- **maturin**: For building Python extensions

## Signature Interface

If you want to use this library, the main interface is that of a *(synchronized) signature scheme*, which is defined in the [Signature trait](https://github.com/b-wagn/hash-sig/blob/main/src/signature.rs). Here is a summary:
- A function `key_gen` to generate keys.
- A function `sign` to sign messages using the secret key with respect to an epoch.
- A function `verify` to verify signatures for a given message, public key, and epoch.

Importantly, each pair of secret key and epoch must not be used twice as input to `sign`.

Further, the secret keys need to be prepared for epochs by calling `sk.advance_preparation()`, which moves the interval `sk.get_prepared_interval()` further to the right.
In particular, we assume that users of the code sign for epochs in order and call `sk.advance_preparation()` at some point in the background
as soon as half of the current prepared interval has passed.


For a signature scheme `T: SignatureScheme`, an example to use this interface may be as follows:
```rust

// generate keys (assume we have an rng)
let (pk, mut sk) = T::key_gen(&mut rng, 0, T::LIFETIME as usize);

// get a random message and a random epoch
let message = rng.random();
let epoch = rng.random_range(0..activation_duration) as u32;

// make sure secret key is prepared for signing in this epoch
let mut iterations = 0;
while !sk.get_prepared_interval().contains(&(epoch as u64)) && iterations < epoch {
    sk.advance_preparation();
    iterations += 1;
}
assert!(sk.get_prepared_interval().contains(&(epoch as u64)));

// now we can sign
let sig = S::sign(&sk, epoch, &message);

// verify the signature
let is_valid = S::verify(&pk, epoch, &message, &sig);
```

See also function `test_signature_scheme_correctness` in [this file](https://github.com/b-wagn/hash-sig/blob/main/src/signature.rs).

## Schemes
The code implements a generic framework from [this paper](https://eprint.iacr.org/2025/055.pdf), which builds XMSS-like hash-based signatures from a primitive called incomparable encodings.
Hardcoded instantiations of this generic framework (using SHA3 or Poseidon2) are defined in `hashsig::signature::generalized_xmss`.
The parameters have been chosen based on the analysis in the paper using Python scripts. Details are as follows:

| Submodule        | Paper / Documentation                                     | Parameters Set With     |
|---------------|-----------------------------------------------------------|--------------------------|
| `instantiations_sha::*`        | [original paper](https://eprint.iacr.org/2025/055.pdf)    | [this repository](https://github.com/b-wagn/hashsig-parameters)   |
| `instantiations_poseidon::*`   | [original paper](https://eprint.iacr.org/2025/055.pdf)    | [this repository](https://github.com/b-wagn/hashsig-parameters)   |
| `instantiations_poseidon_top_level::*`   | [this document](https://eprint.iacr.org/2025/1332), inspired by [this](https://eprint.iacr.org/2025/889.pdf)  | [this repository](https://github.com/b-wagn/hypercube-hashsig-parameters)   |

Instantiations for different key lifetimes and different encodings are given in these modules.

## Tests

Run the tests with

```
cargo test
```

By default, this will exclude some of the tests. In particular, correctness tests for real instantiations take quite long and are excluded.
If you want to run *all* tests, you can use

```
cargo test --release --features slow-tests
```

Removing the `--release` is also an option but tests will take even longer.

## Benchmarks

Benchmarks are provided using criterion.
They take a while, as key generation is expensive, and as a large number of schemes are benchmarked.
Run them with

```
cargo bench
```

The schemes that are benchmarked are hardcoded instantiations of the generic framework, which are defined in `hashsig::signature::generalized_xmss`.
The parameters of these instantiations have been chosen carefully with the aim to achieve a desired security level.
By default, key generation is not benchmarked. There are two options to benchmark it:
1. add the option `--features with-gen-benches-sha` or `--features with-gen-benches-poseidon` or `--features with-gen-benches-poseidon-top-level` to `cargo bench`. Note that this will make benchmarks very slow, as key generation will be repeated within the benchmarks. Especially for Poseidon, this is not recommended.
2. use code similar to the one provided in `src/bin/main.rs` and run it with `cargo run --release`.

If criterion only generates json files, one way to extract all means for all benchmarks easily (without re-running criterion) is to run

```
python3 benchmark-mean.py target
```

Confidence intervals can also be shown via

```
python3 benchmark-mean.py target --intervals
```

## License

Apache Version 2.0.
