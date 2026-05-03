//! Example pqnoize client: connects to 127.0.0.1:9911, completes a
//! pqKK handshake, sends HI/STATUS/BYE in sequence, prints each
//! server reply, exits when L8R arrives.
//!
//! Demo-only static-key derivation — see server.zig for the production
//! caveat.

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
    const stream = try addr.connect(io, .{
        .protocol = .tcp,
        .mode = .stream,
    });
    defer stream.close(io);

    log("client", "connected to 127.0.0.1:{d}", .{port});

    var conn = try pqnoize.Connection.initInitiator(gpa, .{
        .pattern = &pqnoize.pattern.pqKK,
        .role = .initiator,
        .rng = pqnoize.rng.fromIo(&io),
        .s = initiator_static,
        .rs = responder_static.public_key,
    });
    defer conn.deinit();

    try drive(io, stream, &conn);
    log("client", "session ended", .{});
}

const requests = [_][]const u8{ "HI", "STATUS", "BYE" };

fn drive(io: Io, stream: Io.net.Stream, conn: *pqnoize.Connection) !void {
    var read_buf: [4096]u8 = undefined;
    var stream_reader = stream.reader(io, &read_buf);
    var write_buf: [4096]u8 = undefined;
    var stream_writer = stream.writer(io, &write_buf);

    var sent: usize = 0;
    var received: usize = 0;
    var chunk: [4096]u8 = undefined;

    while (received < requests.len) {
        // 1. Once the handshake is established, queue the next request
        //    if we haven't sent everything yet.
        if (conn.isEstablished() and sent < requests.len) {
            const req = requests[sent];
            try conn.send(req);
            log("client", "-> '{s}'", .{req});
            sent += 1;
        }

        // 2. Push outbound bytes (handshake-msg-1 was queued at init,
        //    or a transport frame from the send above).
        const out = conn.outgoing();
        if (out.len > 0) {
            try stream_writer.interface.writeAll(out);
            try stream_writer.interface.flush();
            conn.consumeOutgoing(out.len);
        }

        // 3. Pull bytes from the socket.
        var read_vec: [1][]u8 = .{&chunk};
        const n = stream_reader.interface.readVec(&read_vec) catch |err| switch (err) {
            error.EndOfStream => break,
            error.ReadFailed => {
                if (stream_reader.err) |re| return re;
                return err;
            },
        };
        if (n == 0) continue;
        try conn.recv(chunk[0..n]);

        // 4. Drain any decrypted messages.
        while (conn.nextMessage()) |msg| {
            defer conn.freeMessage(msg);
            log("client", "<- '{s}'", .{msg});
            received += 1;
        }
    }
}

fn log(who: []const u8, comptime fmt: []const u8, args: anytype) void {
    std.debug.print("[{s}] " ++ fmt ++ "\n", .{who} ++ args);
}
