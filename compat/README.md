# compat — Zyli ↔ Hyli Compatibility Corpus

This directory holds the executable spec that the implementation plan calls
out as Phase 0: golden binary fixtures generated from the Rust Hyli reference
implementation, plus the Rust harness that produces them. Zig tests in
`../src/` consume the corpus through `@embedFile`, so the corpus must stay
**deterministic**, **versioned**, and **byte-stable** across regenerations.

## Layout

```
compat/
├── README.md
├── fixture-gen/        Rust binary that links hyli-model and writes fixtures
│   ├── Cargo.toml
│   └── src/main.rs
└── corpus/             Generated, committed-to-git fixtures
    ├── INDEX.md        Human-readable map of fixture name → type/version
    └── borsh/          Borsh-encoded raw bytes, organized by category
        ├── primitives/
        ├── ...
```

Each fixture is a raw `.bin` file containing the Borsh-encoded bytes of a
single value. The Zig side knows the construction parameters by name and
embeds the file at compile time, so we never round-trip through JSON for the
hot equivalence checks.

## Regeneration

```
cd compat/fixture-gen
cargo run --release
```

The generator writes only into `compat/corpus/`. It is idempotent: running
it twice should produce no diffs. Any change to the corpus must be intentional
and committed alongside the matching Zig test changes.

## Versioning rules

- Fixtures are immutable once committed. If a Hyli upstream change alters a
  byte layout, add a new fixture under a new name (e.g. `…_v2.bin`) and
  retire the old one only after the Zig side has been updated.
- The Hyli git revision used to generate each fixture is recorded in
  `corpus/INDEX.md` so we can always reproduce the source of truth.
