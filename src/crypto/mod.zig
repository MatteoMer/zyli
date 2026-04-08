//! `zyli/crypto` — cryptographic primitives Zyli needs for protocol
//! compatibility. This module is intentionally narrow:
//!
//! - The reusable arithmetic and BLS12-381 substrate lives in `zolt-arith`
//!   (Phases 1 and 2 of the implementation plan). `zyli/crypto` is the thin
//!   adapter that turns Hyli protocol structs into the inputs that
//!   `zolt-arith` expects. `zolt_arith` is re-exported here so call sites
//!   touching the substrate go through `zyli.crypto.zolt_arith.*`.
//! - Native verifiers required by replay (`blst`, `sha3_256`, `secp256k1`)
//!   land here as they become necessary, again as adapters over reusable
//!   primitives.
//!
//! For now this module contains:
//!   - `signable` — the "what bytes get BLS-signed" rule.
//!   - `zolt_arith` — re-export of the arithmetic substrate package.

pub const signable = @import("signable.zig");
pub const zolt_arith = @import("zolt_arith");
pub const zolt_arith_adapter = @import("zolt_arith_adapter.zig");
pub const bls = @import("bls.zig");

test {
    _ = signable;
    _ = zolt_arith;
    // Walk into the substrate's submodules so the test runner discovers
    // their tests too. Without this, each zolt_arith subpackage's tests
    // only run when you `cd ../zolt-arith && zig build test` directly.
    _ = zolt_arith.bigint;
    _ = zolt_arith_adapter;
    _ = bls;
}
