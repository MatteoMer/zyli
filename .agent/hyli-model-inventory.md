# Hyli Model Inventory (Borsh + Hash Surfaces)

A snapshot of which Hyli protocol types Zyli must reproduce byte-for-byte
and where to find them in `../hyli/crates/hyli-model`. Used to drive the
golden-vector corpus and the Zig model implementation order.

The first column is the **priority tier**:

- **T0** — leaf primitives. Required by everything else; Borsh layout only.
- **T1** — protocol structs Zyli must encode/decode and hash exactly.
- **T2** — composite messages built on T0/T1 (network, blocks, signed
  containers).
- **T3** — high-level network/runtime envelopes added once T0–T2 pass.

## T0 — Leaf primitives

| Type                  | File                  | Notes                                                |
|-----------------------|-----------------------|------------------------------------------------------|
| `BlockHeight(u64)`    | `contract.rs`         | newtype                                              |
| `BlobIndex(usize)`    | `contract.rs`         | `usize` → Borsh serializes as `u64` on 64-bit hosts? Verify in fixture. |
| `Identity(String)`    | `contract.rs`         | UTF-8 newtype                                        |
| `ContractName(String)`| `contract.rs`         | charset-restricted                                   |
| `Verifier(String)`    | `contract.rs`         |                                                      |
| `ProgramId(Vec<u8>)`  | `contract.rs`         |                                                      |
| `BlobData(Vec<u8>)`   | `contract.rs`         |                                                      |
| `BlobHash(Vec<u8>)`   | `contract.rs`         | digest                                               |
| `TxHash(Vec<u8>)`     | `contract.rs`         | digest                                               |
| `ConsensusProposalHash(Vec<u8>)` | `contract.rs`| also `BlockHash`                                     |
| `StateCommitment(Vec<u8>)`       | `contract.rs`|                                                      |
| `ProofData(Vec<u8>)`             | `contract.rs`|                                                      |
| `ProofDataHash(Vec<u8>)`         | `contract.rs`|                                                      |
| `DataProposalHash(Vec<u8>)`      | `node/mempool.rs`|                                                  |
| `Signature(Vec<u8>)`             | `node/crypto.rs` | BLS signature wrapper                                |
| `ValidatorPublicKey(Vec<u8>)`    | `staking.rs`     | BLS12-381 G1 compressed                              |
| `LaneBytesSize(u64)`             | `staking.rs`     |                                                      |
| `TimestampMs(u128)`              | `utils.rs`       | u128 → little-endian 16 bytes                        |
| `LaneId { operator, suffix }`    | `staking.rs`     | also serialized as `op-suffix` string for hashing    |

## T1 — Protocol structs (Borsh + hash)

| Type                       | File                | Hash function              | Notes |
|----------------------------|---------------------|----------------------------|-------|
| `Blob`                     | `contract.rs`       | sha3_256(name‖data)        | |
| `BlobsHashes`              | `transaction.rs`    | n/a                        | BTreeMap → ordered map encoding |
| `RegisterContractAction`   | `contract.rs`       | sha3_256(custom)           | constructor_metadata excluded from hash |
| `TimeoutWindow` enum       | `contract.rs`       | n/a                        | |
| `OnchainEffect` enum       | `contract.rs`       | sha3_256(custom)           | |
| `HyliOutput`               | `contract.rs`       | n/a                        | zkVM commitment payload; large struct |
| `TxContext`                | `contract.rs`       | n/a                        | |
| `BlobTransaction`          | `transaction.rs`    | sha3_256(identity‖blobs…)  | `hash_cache`/`blobshash_cache` are `#[borsh(skip)]` |
| `ProofTransaction`         | `transaction.rs`    | sha3_256(name‖pid‖ver‖proof_hash) | |
| `VerifiedProofTransaction` | `transaction.rs`    | sha3_256(name‖pid‖ver‖proof_hash) | |
| `TransactionData` enum     | `transaction.rs`    | dispatches                 | enum order: Blob, Proof, VerifiedProof |
| `Transaction`              | `transaction.rs`    | dispatches                 | |
| `TransactionMetadata`      | `transaction.rs`    | n/a                        | |
| `TxId(DataProposalHash, TxHash)` | `node/mempool.rs` | n/a                  | |
| `Calldata`                 | `contract.rs`       | n/a                        | passed to contract zk programs |
| `StakingAction` enum       | `staking.rs`        | n/a                        | inside structured blob data |
| `ValidatorSignature`       | `node/crypto.rs`    | n/a                        | |
| `Signed<T, V>`             | `node/crypto.rs`    | n/a                        | generic envelope; signable bytes are Borsh(msg) |
| `AggregateSignature`       | `node/crypto.rs`    | n/a                        | |
| `ValidatorCandidacy`       | `node/consensus.rs` | n/a                        | |
| `ConsensusStakingAction` enum | `node/consensus.rs` | n/a                     | Bond is boxed in Rust → wire format identical |
| `ConsensusProposal`        | `node/consensus.rs` | sha3_256(custom field-by-field) | NOT a borsh-of-self hash |
| `DataProposalParent` enum  | `node/mempool.rs`   | n/a                        | |
| `DataProposal`             | `node/mempool.rs`   | sha3_256(parent‖tx_hashes) | `hash_cache` is `#[borsh(skip)]` |

## T2 — Larger envelopes (after T1)

- `MempoolStatusEvent` — enum (mempool.rs)
- `MempoolBlockEvent` — uses `SignedBlock` (defined in `block.rs`)
- `block.rs` — `SignedBlock`, `Block`, etc. (not yet read in detail)
- `node/data_availability.rs` — DA messages
- `verifier_worker.rs` — IPC envelopes
- `node/consensus.rs` — full prepare/vote/confirm/commit/timeout messages
  (also live in `consensus` crate, not just hyli-model)

## T3 — Wire/runtime envelopes (Phase 4+)

- TCP framing layer (`hyli-net`)
- Signed message header — exact "what gets signed" bytes per network message
- Handshake / canal connection state

## Hash function summary

- All custom hashes use SHA3-256.
- Several hashes feed pieces of the struct directly into the hasher (not
  Borsh-of-self), so the Zig hash code must mirror the Rust update order
  exactly. Notable cases:
  - `BlobTransaction::hashed`
  - `ProofTransaction::hashed`
  - `VerifiedProofTransaction::hashed`
  - `Blob::hashed`
  - `ProofData::hashed`
  - `RegisterContractAction::hashed` (skips constructor_metadata)
  - `OnchainEffect::hashed`
  - `ConsensusProposal::hashed`
  - `DataProposal::hashed`

## Quirks to lock down with fixtures

- `BlobIndex(usize)` — Borsh in Rust serializes `usize` as `u64` (the
  `borsh` crate guarantees a fixed `u64` representation regardless of
  host pointer size). Lock down with a fixture, since Zig's analogous
  `usize` is **not** a wire-stable choice.
- `BTreeMap` keys — Borsh writes them sorted by serialized key bytes.
  Mirror with a comparator on encode in Zig.
- `#[borsh(skip)]` fields are absent from the wire (`hash_cache`,
  `blobshash_cache`).
- Box<T> is invisible on the wire — `ConsensusStakingAction::Bond { candidate: Box<...> }`
  encodes the same as the unboxed form.
- `TimestampMs(u128)` — 16 bytes little-endian. Confirm with fixture.
- Strings are length-prefixed UTF-8 (`u32` length).

## Order of attack

1. T0 leaf primitives — single-value Borsh fixtures.
2. `Blob`, `BlobTransaction`, `ProofTransaction`, `VerifiedProofTransaction`,
   `Transaction` and their hashes.
3. `DataProposal` and `DataProposalHash`.
4. `ConsensusProposal` and `ConsensusProposalHash` (custom hash order).
5. `Signed<T, V>` envelope and the BLS-signed payload bytes.
6. T2 envelopes once Phase 2 BLS lands.
