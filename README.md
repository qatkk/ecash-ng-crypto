# ecash-ng-crypto

Prototype of a threshold blind credential scheme for e-cash: Coconut-style
blind issuance of Pointcheval–Sanders signatures over BLS12-381, with three
hidden attributes per note (amount, serial secret, spend condition) and
unlinkable zero-knowledge spends.

**A full description of the scheme in mathematical notation is available at
[joschisan.github.io/ecash-ng-crypto](https://joschisan.github.io/ecash-ng-crypto/).**

## Layout

- `src/lib.rs` — protocol flow: issuance request, blind signing, share
  aggregation, unblinding, re-randomization, spend
- `src/issuance.rs` — issuance commitments and Σ-proof
- `src/spend.rs` — spend Σ-proof
- `src/generators.rs` — nothing-up-my-sleeve generators
- `src/hash.rs` — hash-to-group / hash-to-scalar helpers

## Usage

```
cargo test    # roundtrip: issue 5-of-7, aggregate, spend
cargo bench   # issuance prove/verify benchmarks
```

This is unreviewed prototype code — do not use in production.
