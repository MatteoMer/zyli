//! `zyli/wire` — TCP framing, peer connection state, and the `TcpMessage`
//! envelope Hyli uses for every P2P byte that crosses the wire.
//!
//! Membership rules (mirrored from the implementation plan):
//! - No protocol/business logic. The wire module is responsible for the
//!   bytes-to-frames-to-messages transformation and nothing else.
//! - All Borsh encoding/decoding happens through `zyli/model/borsh.zig` so
//!   there is exactly one source of truth for Borsh on the Zig side.
//! - Public types here represent the wire shapes that Hyli sends, not
//!   higher-level protocol messages.

pub const framing = @import("framing.zig");
pub const tcp_message = @import("tcp_message.zig");
pub const handshake = @import("handshake.zig");
pub const protocol = @import("protocol.zig");

test {
    _ = framing;
    _ = tcp_message;
    _ = handshake;
    _ = protocol;
}
