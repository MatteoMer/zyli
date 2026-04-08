//! `zyli/crypto` — cryptographic primitives Zyli needs for protocol
//! compatibility. This module is intentionally narrow:
//!
//! - The reusable arithmetic and BLS12-381 substrate lives in `zolt-arith`
//!   (Phases 1 and 2 of the implementation plan). `zyli/crypto` is the thin
//!   adapter that turns Hyli protocol structs into the inputs that
//!   `zolt-arith` expects.
//! - Native verifiers required by replay (`blst`, `sha3_256`, `secp256k1`)
//!   land here as they become necessary, again as adapters over reusable
//!   primitives.
//!
//! For now this module only contains `signable`, which encodes the
//! "what bytes get BLS-signed" rule.

pub const signable = @import("signable.zig");

test {
    _ = signable;
}
