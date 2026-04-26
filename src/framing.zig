//! Length-prefixed framing for the transport.
//!
//! Wire format: `[u16 big-endian length][length bytes of payload]`.
//! The same framing carries both handshake messages and post-Split
//! transport ciphertexts. Per Noise spec, the maximum payload of a
//! single transport message is 65535 bytes — exactly what the u16
//! prefix supports.
//!
//! Both `FrameReader` and `FrameWriter` are sans-IO: bytes flow in and
//! out via slices, the caller drives any actual socket.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const max_frame_payload: usize = std.math.maxInt(u16);
pub const frame_header_len: usize = 2;

pub const Error = error{
    /// Caller asked us to frame a payload larger than the wire format
    /// supports. Application-level chunking is needed.
    FrameTooLarge,
} || Allocator.Error;

/// Encode `payload_len` into the 2-byte big-endian header.
pub fn writeFrameHeader(out: *[frame_header_len]u8, payload_len: usize) Error!void {
    if (payload_len > max_frame_payload) return error.FrameTooLarge;
    std.mem.writeInt(u16, out, @intCast(payload_len), .big);
}

pub fn readFrameHeader(bytes: *const [frame_header_len]u8) usize {
    return std.mem.readInt(u16, bytes, .big);
}

/// Accumulates inbound bytes from the network and yields complete frames.
/// The caller pushes whatever bytes the socket gave it (which may straddle
/// frame boundaries or be a fragment of a single frame); peek/pop deliver
/// complete payloads.
pub const FrameReader = struct {
    buf: std.ArrayList(u8),

    pub const empty: FrameReader = .{ .buf = .empty };

    pub fn deinit(self: *FrameReader, gpa: Allocator) void {
        self.buf.deinit(gpa);
    }

    pub fn push(self: *FrameReader, gpa: Allocator, bytes: []const u8) Error!void {
        try self.buf.appendSlice(gpa, bytes);
    }

    /// Borrowed payload of the next complete frame, or null if incomplete.
    /// The slice is invalidated by the next `push` or `pop` call.
    pub fn peek(self: FrameReader) ?[]const u8 {
        if (self.buf.items.len < frame_header_len) return null;
        const header: *const [frame_header_len]u8 = self.buf.items[0..frame_header_len];
        const payload_len = readFrameHeader(header);
        const total = frame_header_len + payload_len;
        if (self.buf.items.len < total) return null;
        return self.buf.items[frame_header_len..total];
    }

    /// Discard the frame returned by the most recent `peek`. Compacts
    /// any trailing bytes (the start of a subsequent frame) to the front.
    pub fn pop(self: *FrameReader) void {
        std.debug.assert(self.buf.items.len >= frame_header_len);
        const header: *const [frame_header_len]u8 = self.buf.items[0..frame_header_len];
        const payload_len = readFrameHeader(header);
        const total = frame_header_len + payload_len;
        std.debug.assert(self.buf.items.len >= total);
        const rest = self.buf.items[total..];
        std.mem.copyForwards(u8, self.buf.items[0..rest.len], rest);
        self.buf.shrinkRetainingCapacity(rest.len);
    }
};

/// Buffers outbound frames waiting to be written to the network. Caller
/// reads via `outgoing()` and acks consumed bytes via `consume(n)` once
/// the socket has accepted them.
pub const FrameWriter = struct {
    buf: std.ArrayList(u8),

    pub const empty: FrameWriter = .{ .buf = .empty };

    pub fn deinit(self: *FrameWriter, gpa: Allocator) void {
        self.buf.deinit(gpa);
    }

    pub fn push(self: *FrameWriter, gpa: Allocator, payload: []const u8) Error!void {
        if (payload.len > max_frame_payload) return error.FrameTooLarge;
        var hdr: [frame_header_len]u8 = undefined;
        try writeFrameHeader(&hdr, payload.len);
        try self.buf.ensureUnusedCapacity(gpa, frame_header_len + payload.len);
        self.buf.appendSliceAssumeCapacity(&hdr);
        self.buf.appendSliceAssumeCapacity(payload);
    }

    /// Bytes the caller should write to the socket. Borrowed; invalidated
    /// by `push` or `consume`.
    pub fn outgoing(self: FrameWriter) []const u8 {
        return self.buf.items;
    }

    pub fn consume(self: *FrameWriter, n: usize) void {
        std.debug.assert(n <= self.buf.items.len);
        const rest = self.buf.items[n..];
        std.mem.copyForwards(u8, self.buf.items[0..rest.len], rest);
        self.buf.shrinkRetainingCapacity(rest.len);
    }
};

// ── Inline tests ──────────────────────────────────────────────────────────

const testing = std.testing;

test "header round-trip across edge values" {
    var hdr: [2]u8 = undefined;
    try writeFrameHeader(&hdr, 0);
    try testing.expectEqualSlices(u8, &.{ 0, 0 }, &hdr);
    try testing.expectEqual(@as(usize, 0), readFrameHeader(&hdr));

    try writeFrameHeader(&hdr, 1);
    try testing.expectEqualSlices(u8, &.{ 0, 1 }, &hdr);

    try writeFrameHeader(&hdr, 256);
    try testing.expectEqualSlices(u8, &.{ 1, 0 }, &hdr);

    try writeFrameHeader(&hdr, max_frame_payload);
    try testing.expectEqualSlices(u8, &.{ 0xff, 0xff }, &hdr);
    try testing.expectEqual(max_frame_payload, readFrameHeader(&hdr));
}

test "writeFrameHeader rejects oversize payloads" {
    var hdr: [2]u8 = undefined;
    try testing.expectError(error.FrameTooLarge, writeFrameHeader(&hdr, max_frame_payload + 1));
}

test "FrameReader: returns null until a complete frame has arrived" {
    const gpa = testing.allocator;
    var r: FrameReader = .empty;
    defer r.deinit(gpa);

    try r.push(gpa, &.{0x00});
    try testing.expect(r.peek() == null);
    try r.push(gpa, &.{0x05});
    try testing.expect(r.peek() == null);
    try r.push(gpa, "hel");
    try testing.expect(r.peek() == null);
    try r.push(gpa, "lo");
    try testing.expectEqualSlices(u8, "hello", r.peek().?);

    r.pop();
    try testing.expect(r.peek() == null);
}

test "FrameReader: handles two frames pushed in one chunk" {
    const gpa = testing.allocator;
    var r: FrameReader = .empty;
    defer r.deinit(gpa);

    try r.push(gpa, &.{ 0x00, 0x03 });
    try r.push(gpa, "abc");
    try r.push(gpa, &.{ 0x00, 0x02 });
    try r.push(gpa, "de");

    try testing.expectEqualSlices(u8, "abc", r.peek().?);
    r.pop();
    try testing.expectEqualSlices(u8, "de", r.peek().?);
    r.pop();
    try testing.expect(r.peek() == null);
}

test "FrameReader: byte-at-a-time feed (worst-case TCP fragmentation)" {
    const gpa = testing.allocator;
    var r: FrameReader = .empty;
    defer r.deinit(gpa);

    const frame = [_]u8{ 0x00, 0x04, 'a', 'b', 'c', 'd' };
    for (frame[0 .. frame.len - 1]) |byte| {
        try r.push(gpa, &.{byte});
        try testing.expect(r.peek() == null);
    }
    try r.push(gpa, &.{frame[frame.len - 1]});
    try testing.expectEqualSlices(u8, "abcd", r.peek().?);
}

test "FrameReader: accepts a zero-length frame" {
    const gpa = testing.allocator;
    var r: FrameReader = .empty;
    defer r.deinit(gpa);

    try r.push(gpa, &.{ 0x00, 0x00 });
    const peeked = r.peek().?;
    try testing.expectEqual(@as(usize, 0), peeked.len);
    r.pop();
    try testing.expect(r.peek() == null);
}

test "FrameWriter: round-trip via FrameReader" {
    const gpa = testing.allocator;
    var w: FrameWriter = .empty;
    defer w.deinit(gpa);

    try w.push(gpa, "first");
    try w.push(gpa, "second");

    var r: FrameReader = .empty;
    defer r.deinit(gpa);
    try r.push(gpa, w.outgoing());

    try testing.expectEqualSlices(u8, "first", r.peek().?);
    r.pop();
    try testing.expectEqualSlices(u8, "second", r.peek().?);
}

test "FrameWriter: consume drops a prefix and preserves the tail" {
    const gpa = testing.allocator;
    var w: FrameWriter = .empty;
    defer w.deinit(gpa);
    try w.push(gpa, "abc");
    try w.push(gpa, "de");

    // First frame is 5 bytes on the wire (2 hdr + 3 payload).
    w.consume(5);
    var r: FrameReader = .empty;
    defer r.deinit(gpa);
    try r.push(gpa, w.outgoing());
    try testing.expectEqualSlices(u8, "de", r.peek().?);
}

test "FrameWriter: rejects oversize push" {
    const gpa = testing.allocator;
    var w: FrameWriter = .empty;
    defer w.deinit(gpa);
    const huge = try gpa.alloc(u8, max_frame_payload + 1);
    defer gpa.free(huge);
    try testing.expectError(error.FrameTooLarge, w.push(gpa, huge));
}
