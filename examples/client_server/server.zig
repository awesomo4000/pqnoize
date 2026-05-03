//! Example pqnoize server: listens on 127.0.0.1:9911 for one client,
//! completes a pqKK handshake, then runs the demo HI/STATUS/BYE
//! protocol. Exits cleanly after the BYE/L8R exchange.
//!
//! Demo-only: derives static keys from a hardcoded SeedStream label so
//! the matching client can compute the same keypair without any
//! out-of-band exchange. Production deployments would load static
//! keys from secure storage and verify peer pubkeys via a trust model
//! (config file, signed catalog, TOFU on first connect, etc.).

const std = @import("std");
const Io = std.Io;
const pqnoize = @import("pqnoize");

const port: u16 = 9911;
const initiator_label = "pqnoize-example-initiator";
const responder_label = "pqnoize-example-responder";

fn deriveStatic(label: []const u8) !pqnoize.kem.Kem.KeyPair {
    var seed = pqnoize.testing.SeedStream.init(label);
    return pqnoize.testing.keypair(&seed);
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const io = init.io;

    const initiator_static = try deriveStatic(initiator_label);
    const responder_static = try deriveStatic(responder_label);

    var addr: Io.net.IpAddress = .{ .ip4 = .{
        .bytes = .{ 127, 0, 0, 1 },
        .port = port,
    } };
    var server = try addr.listen(io, .{
        .protocol = .tcp,
        .mode = .stream,
        .reuse_address = true,
    });
    defer server.deinit(io);

    log("server", "listening on 127.0.0.1:{d}", .{port});

    const stream = try server.accept(io);
    defer stream.close(io);

    log("server", "client connected", .{});

    var conn = try pqnoize.Connection.initResponder(gpa, .{
        .pattern = &pqnoize.pattern.pqKK,
        .role = .responder,
        .rng = pqnoize.rng.fromIo(&io),
        .s = responder_static,
        .rs = initiator_static.public_key,
    });
    defer conn.deinit();

    try drive(io, stream, &conn);
    log("server", "session ended", .{});
}

/// Driver loop: shuttle bytes between the TCP stream and Connection,
/// react to each decrypted application message. Returns cleanly on
/// peer EOF or after replying to BYE.
fn drive(io: Io, stream: Io.net.Stream, conn: *pqnoize.Connection) !void {
    var read_buf: [4096]u8 = undefined;
    var stream_reader = stream.reader(io, &read_buf);
    var write_buf: [4096]u8 = undefined;
    var stream_writer = stream.writer(io, &write_buf);

    var saw_bye = false;
    var chunk: [4096]u8 = undefined;

    while (true) {
        // 1. Push any queued outbound bytes to the socket.
        const out = conn.outgoing();
        if (out.len > 0) {
            try stream_writer.interface.writeAll(out);
            try stream_writer.interface.flush();
            conn.consumeOutgoing(out.len);
        }

        // After flushing the L8R reply we're done.
        if (saw_bye) return;

        // 2. Pull some bytes from the socket.
        var read_vec: [1][]u8 = .{&chunk};
        const n = stream_reader.interface.readVec(&read_vec) catch |err| switch (err) {
            error.EndOfStream => return,
            error.ReadFailed => {
                if (stream_reader.err) |re| return re;
                return err;
            },
        };
        if (n == 0) continue;
        try conn.recv(chunk[0..n]);

        // 3. Process any decrypted application messages.
        while (conn.nextMessage()) |msg| {
            defer conn.freeMessage(msg);
            const reply = chooseReply(msg);
            log("server", "<- '{s}'  -> '{s}'", .{ msg, reply });
            try conn.send(reply);
            if (std.mem.eql(u8, msg, "BYE")) saw_bye = true;
        }
    }
}

fn chooseReply(req: []const u8) []const u8 {
    if (std.mem.eql(u8, req, "HI")) return "HI";
    if (std.mem.eql(u8, req, "STATUS")) return "GOOD";
    if (std.mem.eql(u8, req, "BYE")) return "L8R";
    return "?";
}

fn log(who: []const u8, comptime fmt: []const u8, args: anytype) void {
    std.debug.print("[{s}] " ++ fmt ++ "\n", .{who} ++ args);
}
