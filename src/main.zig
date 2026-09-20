const std = @import("std");
const Io = std.Io;
const net = std.Io.net;

const ID_LEN: usize = 6;
const ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789";
const MAX_URL_LEN: usize = 4096; // cap on shortened target URLs
const MAX_BODY: usize = 16384; // cap on POST request bodies
const DEFAULT_TTL: u64 = 48 * 3600;
const MAX_TTL: u64 = 180 * 86400; // 6 months; must fit in i64 for expiry math
const RATE_LIMIT: u64 = 100; // links per IP per window
const RATE_WINDOW: i64 = 3600; // seconds per rate window
const DATA_DIR = "data";

fn nowSecs(io: Io) i64 {
    return @intCast(@divTrunc(Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s));
}

const SpinLock = struct {
    state: std.atomic.Mutex = .unlocked,

    fn lock(self: *SpinLock) void {
        while (!self.state.tryLock()) {
            std.atomic.spinLoopHint();
        }
    }

    fn unlock(self: *SpinLock) void {
        self.state.unlock();
    }
};

const RateWindow = struct {
    count: u64,
    reset_at: i64,
};

const ServerState = struct {
    allocator: std.mem.Allocator,
    ip_ratelimits: std.StringHashMap(RateWindow),
    mutex: SpinLock,

    fn init(allocator: std.mem.Allocator, io: Io) !ServerState {
        try std.Io.Dir.cwd().createDirPath(io, DATA_DIR);
        return ServerState{
            .allocator = allocator,
            .ip_ratelimits = std.StringHashMap(RateWindow).init(allocator),
            .mutex = .{},
        };
    }

    fn deinit(self: *ServerState) void {
        var it = self.ip_ratelimits.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.ip_ratelimits.deinit();
    }
};

var state: ServerState = undefined;

// Builds a per-IP rate-limit key. Must NOT include the source port, otherwise
// each new TCP connection gets its own bucket and the limit never triggers.
fn getClientIP(addr: net.IpAddress) ![]u8 {
    return switch (addr) {
        .ip4 => |ip4| {
            const b = ip4.bytes;
            return std.fmt.allocPrint(state.allocator, "{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] });
        },
        .ip6 => |ip6| {
            const b = ip6.bytes;
            // Group IPv4-mapped IPv6 addresses with their IPv4 peers.
            if (std.mem.eql(u8, b[0..10], &[_]u8{0} ** 10) and b[10] == 0xff and b[11] == 0xff) {
                return std.fmt.allocPrint(state.allocator, "{d}.{d}.{d}.{d}", .{ b[12], b[13], b[14], b[15] });
            }
            const value = std.mem.readInt(u128, b[0..16], .big);
            return std.fmt.allocPrint(state.allocator, "{x}", .{value});
        },
    };
}

fn checkRateLimit(io: Io, ip: []const u8) !bool {
    state.mutex.lock();
    defer state.mutex.unlock();

    const now = nowSecs(io);
    const gop = try state.ip_ratelimits.getOrPut(ip);
    if (!gop.found_existing) {
        gop.key_ptr.* = try state.allocator.dupe(u8, ip);
        gop.value_ptr.* = .{ .count = 0, .reset_at = now + RATE_WINDOW };
    }

    if (now > gop.value_ptr.reset_at) {
        gop.value_ptr.count = 0;
        gop.value_ptr.reset_at = now + RATE_WINDOW;
    }

    if (gop.value_ptr.count >= RATE_LIMIT) return false;
    gop.value_ptr.count += 1;
    return true;
}

fn parseTTL(ttl_str: []const u8) u64 {
    if (ttl_str.len < 2) return DEFAULT_TTL;
    const num = std.fmt.parseInt(u64, ttl_str[0 .. ttl_str.len - 1], 10) catch return DEFAULT_TTL;
    const unit = ttl_str[ttl_str.len - 1];
    const multiplier: u64 = switch (unit) {
        'm' => 60,
        'h' => 3600,
        'd' => 86400,
        'w' => 7 * 86400,
        'M' => 30 * 86400,
        else => return DEFAULT_TTL,
    };
    const ttl = std.math.mul(u64, num, multiplier) catch std.math.maxInt(u64);
    return @min(ttl, MAX_TTL);
}

pub fn sendResponse(writer: *std.Io.Writer, status: u16, content_type: []const u8, body: []const u8, connection: []const u8) !void {
    const status_text = switch (status) {
        200 => "OK",
        302 => "Found",
        400 => "Bad Request",
        404 => "Not Found",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        else => "Unknown",
    };
    const header = try std.fmt.allocPrint(state.allocator,
        "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nConnection: {s}\r\n\r\n",
        .{ status, status_text, content_type, body.len, connection });
    defer state.allocator.free(header);
    try writer.writeAll(header);
    try writer.writeAll(body);
}

fn sendRedirect(writer: *std.Io.Writer, location: []const u8, connection: []const u8) !void {
    const header = try std.fmt.allocPrint(state.allocator,
        "HTTP/1.1 302 Found\r\nLocation: {s}\r\nContent-Length: 0\r\nConnection: {s}\r\n\r\n",
        .{ location, connection });
    defer state.allocator.free(header);
    try writer.writeAll(header);
}

fn sendFile(io: Io, writer: *std.Io.Writer, file_path: []const u8, content_type: []const u8, connection: []const u8) !void {
    const cwd = std.Io.Dir.cwd();
    const stat = cwd.statFile(io, file_path, .{}) catch {
        try sendResponse(writer, 404, "text/plain", "Not found", connection);
        return;
    };

    var file = try cwd.openFile(io, file_path, .{});
    defer file.close(io);

    const header = try std.fmt.allocPrint(state.allocator,
        "HTTP/1.1 200 OK\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nConnection: {s}\r\n\r\n",
        .{ content_type, stat.size, connection });
    defer state.allocator.free(header);
    try writer.writeAll(header);

    var buf: [65536]u8 = undefined;
    var offset: u64 = 0;
    while (true) {
        const n = try file.readPositional(io, &[_][]u8{buf[0..]}, offset);
        if (n == 0) break;
        try writer.writeAll(buf[0..n]);
        offset += n;
    }
}

// Extracts the numeric value of `"name": ...` from JSON, tolerant of optional
// whitespace after the colon. Returns null if missing or not an integer.
fn jsonFieldInt(data: []const u8, comptime name: []const u8) ?i64 {
    var start = std.mem.indexOf(u8, data, "\"" ++ name ++ "\"") orelse return null;
    start += name.len + 2;
    while (start < data.len and data[start] != ':') : (start += 1) {}
    start += 1;
    while (start < data.len and (data[start] == ' ' or data[start] == '\t')) : (start += 1) {}
    const value_start = start;
    while (start < data.len and data[start] >= '0' and data[start] <= '9') : (start += 1) {}
    if (start == value_start) return null;
    return std.fmt.parseInt(i64, data[value_start..start], 10) catch null;
}

// Extracts the string value of `"name": "..."` from JSON, tolerant of optional
// whitespace after the colon. Returns a slice into `data`.
fn jsonFieldStr(data: []const u8, comptime name: []const u8) ?[]const u8 {
    var start = std.mem.indexOf(u8, data, "\"" ++ name ++ "\"") orelse return null;
    start += name.len + 2;
    while (start < data.len and data[start] != ':') : (start += 1) {}
    start += 1;
    while (start < data.len and (data[start] == ' ' or data[start] == '\t')) : (start += 1) {}
    if (start >= data.len or data[start] != '"') return null;
    start += 1;
    const value_start = start;
    while (start < data.len and data[start] != '"') : (start += 1) {}
    if (start == value_start) return null;
    return data[value_start..start];
}

fn hexVal(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

fn urlDecode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var out = try allocator.alloc(u8, input.len);
    var n: usize = 0;
    var i: usize = 0;
    while (i < input.len) {
        if (input[i] == '%' and i + 2 < input.len) {
            const hi = hexVal(input[i + 1]) orelse {
                out[n] = '%';
                n += 1;
                i += 1;
                continue;
            };
            const lo = hexVal(input[i + 2]) orelse {
                out[n] = '%';
                n += 1;
                i += 1;
                continue;
            };
            out[n] = hi * 16 + lo;
            n += 1;
            i += 3;
        } else {
            out[n] = input[i];
            n += 1;
            i += 1;
        }
    }
    return out[0..n];
}

// Links are 6 lowercase alphanumeric characters. Comparison is case-insensitive
// so AbCdEf and abcdef resolve to the same link. Caller must ensure
// buf.len >= id.len.
fn normalizeId(id: []const u8, buf: []u8) []u8 {
    for (id, 0..) |c, i| buf[i] = std.ascii.toLower(c);
    return buf[0..id.len];
}

fn isValidId(id: []const u8) bool {
    if (id.len != ID_LEN) return false;
    for (id) |c| {
        if (!std.ascii.isAlphanumeric(c)) return false;
    }
    return true;
}

// Generate a fresh 6-character id from a CSPRNG-backed I/O object.
fn genId(io: Io) [ID_LEN]u8 {
    var raw: [ID_LEN]u8 = undefined;
    io.random(&raw);
    var id: [ID_LEN]u8 = undefined;
    for (raw, 0..) |b, i| id[i] = ALPHABET[b % ALPHABET.len];
    return id;
}

fn isValidUrl(url: []const u8) bool {
    if (url.len < 9 or url.len > MAX_URL_LEN) return false;
    var scheme_len: usize = 0;
    if (isScheme(url, "https://")) {
        scheme_len = "https://".len;
    } else if (isScheme(url, "http://")) {
        scheme_len = "http://".len;
    } else {
        return false;
    }
    const rest = url[scheme_len..];
    // Must have a host (not "http:///path").
    if (rest.len == 0 or rest[0] == '/') return false;
    // Reject characters that break the JSON store, the Location header, or
    // form encoding: controls, whitespace, quotes, backslashes.
    for (url) |c| {
        if (c < 0x21 or c == 0x7f or c == '"' or c == '\\') return false;
    }
    return true;
}

fn isScheme(url: []const u8, comptime prefix: []const u8) bool {
    if (url.len < prefix.len) return false;
    for (url[0..prefix.len], 0..) |c, i| {
        if (std.ascii.toLower(c) != prefix[i]) return false;
    }
    return true;
}

fn linkPath(id: []const u8) ![]u8 {
    return std.fmt.allocPrint(state.allocator, "{s}/{s}.json", .{ DATA_DIR, id });
}

fn linkExists(io: Io, id: []const u8) !bool {
    const cwd = std.Io.Dir.cwd();
    const path = try linkPath(id);
    defer state.allocator.free(path);
    var f = cwd.openFile(io, path, .{}) catch return false;
    f.close(io);
    return true;
}

fn saveLink(io: Io, id: []const u8, url: []const u8, ttl_seconds: u64) !void {
    const path = try linkPath(id);
    defer state.allocator.free(path);

    const cwd = std.Io.Dir.cwd();
    var file = try cwd.createFile(io, path, .{});
    defer file.close(io);

    var buf: [4096]u8 = undefined;
    var w = file.writer(io, &buf);

    const now = nowSecs(io);
    try w.interface.print("{{ \"url\": \"{s}\", \"created_at\": {d}, \"ttl_seconds\": {d} }}", .{ url, now, ttl_seconds });
    try w.flush();
}

const ParsedRequest = struct {
    method: []const u8,
    path: []const u8,
    content_length: usize,
    host: []const u8,
    connection: []const u8,
};

fn parseRequestHeaders(data: []const u8) !ParsedRequest {
    var result = ParsedRequest{
        .method = "",
        .path = "",
        .content_length = 0,
        .host = "",
        .connection = "keep-alive",
    };

    var lines = std.mem.splitScalar(u8, data, '\n');
    const first = lines.next() orelse return error.InvalidRequest;
    var parts = std.mem.splitScalar(u8, first, ' ');
    result.method = std.mem.trim(u8, (parts.next() orelse return error.InvalidRequest), "\r\n");
    result.path = std.mem.trim(u8, (parts.next() orelse return error.InvalidRequest), "\r\n");

    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, "\r\n");
        if (trimmed.len == 0) break;

        if (std.mem.startsWith(u8, trimmed, "Content-Length: ")) {
            result.content_length = std.fmt.parseInt(usize, trimmed[16..], 10) catch 0;
        } else if (std.mem.startsWith(u8, trimmed, "Host: ")) {
            result.host = std.mem.trim(u8, trimmed[6..], "\r\n");
        } else if (std.mem.startsWith(u8, trimmed, "Connection: ")) {
            result.connection = std.mem.trim(u8, trimmed[12..], "\r\n");
        }
    }

    return result;
}

fn handleCreate(io: Io, addr: net.IpAddress, body: []const u8, host: []const u8, writer: *std.Io.Writer, connection: []const u8) !void {
    // Parse the target URL. Accepts `application/json` ({url, ttl}) or
    // `application/x-www-form-urlencoded` (url=...&ttl=...).
    var url: []const u8 = "";
    var ttl: []const u8 = "";
    var alloc_url: ?[]u8 = null;
    var alloc_ttl: ?[]u8 = null;
    defer {
        if (alloc_url) |v| state.allocator.free(v);
        if (alloc_ttl) |v| state.allocator.free(v);
    }

    if (body.len == 0) {
        try sendResponse(writer, 400, "text/plain", "Missing body", connection);
        return;
    }

    if (body.len > 0 and body[0] == '{') {
        url = jsonFieldStr(body, "url") orelse "";
        ttl = jsonFieldStr(body, "ttl") orelse "";
    } else {
        // form-encoded: url=...&ttl=...
        var it = std.mem.splitScalar(u8, body, '&');
        while (it.next()) |pair| {
            if (std.mem.startsWith(u8, pair, "url=")) {
                const decoded = try urlDecode(state.allocator, pair[4..]);
                alloc_url = decoded;
                url = decoded;
            } else if (std.mem.startsWith(u8, pair, "ttl=")) {
                const decoded = try urlDecode(state.allocator, pair[4..]);
                alloc_ttl = decoded;
                ttl = decoded;
            }
        }
    }

    if (url.len == 0) {
        try sendResponse(writer, 400, "text/plain", "Missing url", connection);
        return;
    }
    if (!isValidUrl(url)) {
        try sendResponse(writer, 400, "text/plain", "Invalid url (must be http:// or https://)", connection);
        return;
    }

    const ip = try getClientIP(addr);
    defer state.allocator.free(ip);
    if (!try checkRateLimit(io, ip)) {
        try sendResponse(writer, 429, "text/plain", "Rate limit exceeded, try again later", connection);
        return;
    }

    const ttl_seconds = parseTTL(ttl);

    // Generate an id, retrying on the rare collision.
    var id: [ID_LEN]u8 = undefined;
    var made: bool = false;
    for (0..8) |_| {
        id = genId(io);
        if (!try linkExists(io, &id)) {
            made = true;
            break;
        }
    }
    if (!made) {
        try sendResponse(writer, 500, "text/plain", "Could not allocate id", connection);
        return;
    }

    try saveLink(io, &id, url, ttl_seconds);

    const short = if (host.len > 0)
        try std.fmt.allocPrint(state.allocator, "http://{s}/{s}", .{ host, &id })
    else
        try std.fmt.allocPrint(state.allocator, "/{s}", .{&id});
    defer state.allocator.free(short);
    const json = try std.fmt.allocPrint(state.allocator, "{{\"id\":\"{s}\",\"short\":\"{s}\",\"url\":\"{s}\",\"ttl_seconds\":{d}}}", .{ &id, short, url, ttl_seconds });
    defer state.allocator.free(json);

    try sendResponse(writer, 200, "application/json", json, connection);
}

fn handleRedirect(io: Io, writer: *std.Io.Writer, id: []const u8, connection: []const u8) !void {
    const cwd = std.Io.Dir.cwd();
    const meta_path = try linkPath(id);
    defer state.allocator.free(meta_path);

    const data = cwd.readFileAlloc(io, meta_path, state.allocator, .limited(4096)) catch {
        try sendResponse(writer, 404, "text/plain", "Not found", connection);
        return;
    };
    defer state.allocator.free(data);

    const created_at = jsonFieldInt(data, "created_at") orelse {
        try sendResponse(writer, 404, "text/plain", "Not found", connection);
        return;
    };
    const ttl_seconds = jsonFieldInt(data, "ttl_seconds") orelse {
        try sendResponse(writer, 404, "text/plain", "Not found", connection);
        return;
    };
    if (nowSecs(io) > created_at + @as(i64, @intCast(ttl_seconds))) {
        try sendResponse(writer, 404, "text/plain", "Expired", connection);
        return;
    }
    const url = jsonFieldStr(data, "url") orelse {
        try sendResponse(writer, 404, "text/plain", "Not found", connection);
        return;
    };

    try sendRedirect(writer, url, connection);
}

fn handleConnection(io: Io, stream: net.Stream, addr: net.IpAddress) !void {
    defer stream.close(io);

    const IdleTimeout = struct {
        tv_sec: i64,
        tv_usec: i64,
    };
    const tv = IdleTimeout{ .tv_sec = 60, .tv_usec = 0 };
    std.posix.setsockopt(stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};

    var read_buf: [8192]u8 = undefined;
    var reader_obj = stream.reader(io, &read_buf);
    var reader = &reader_obj.interface;

    var write_buf: [4096]u8 = undefined;
    var writer_obj = stream.writer(io, &write_buf);
    const writer = &writer_obj.interface;
    defer writer_obj.interface.flush() catch {};

    while (true) {
        var header_buf: [8192]u8 = undefined;
        var header_len: usize = 0;
        var found_end = false;

        while (header_len < header_buf.len) {
            const byte = reader.takeByte() catch return;
            header_buf[header_len] = byte;
            header_len += 1;

            if (header_len >= 4 and std.mem.eql(u8, header_buf[header_len - 4 .. header_len], "\r\n\r\n")) {
                found_end = true;
                break;
            }
        }

        if (!found_end) {
            try sendResponse(writer, 400, "text/plain", "Bad request", "close");
            return;
        }

        const req = parseRequestHeaders(header_buf[0..header_len]) catch {
            try sendResponse(writer, 400, "text/plain", "Bad request", "close");
            return;
        };

        const keep_alive = !std.mem.eql(u8, req.connection, "close");
        const connection: []const u8 = if (keep_alive) "keep-alive" else "close";

        var body: []u8 = &[_]u8{};
        var body_owned = false;
        var request_error = false;

        if (req.content_length > 0) {
            if (req.content_length > MAX_BODY) {
                try sendResponse(writer, 413, "text/plain", "Body too large", connection);
                return;
            }

            body = try state.allocator.alloc(u8, req.content_length);
            body_owned = true;

            var received: usize = 0;
            while (received < req.content_length) {
                const n = reader.readSliceShort(body[received..]) catch {
                    request_error = true;
                    break;
                };
                if (n == 0) break;
                received += n;
            }
        }

        if (!request_error) {
            if (std.mem.eql(u8, req.path, "/")) {
                try sendFile(io, writer, "src/index.html", "text/html", connection);
            } else if (std.mem.eql(u8, req.path, "/a.png")) {
                try sendFile(io, writer, "src/a.png", "image/png", connection);
            } else if (std.mem.eql(u8, req.path, "/api")) {
                if (!std.mem.eql(u8, req.method, "POST")) {
                    try sendResponse(writer, 405, "text/plain", "Method not allowed", connection);
                } else {
                    try handleCreate(io, addr, body, req.host, writer, connection);
                }
            } else if (req.path.len == ID_LEN + 1 and req.path[0] == '/') {
                var id_buf: [ID_LEN]u8 = undefined;
                const id = normalizeId(req.path[1..], &id_buf);
                if (!isValidId(id)) {
                    try sendResponse(writer, 404, "text/plain", "Not found", connection);
                } else {
                    try handleRedirect(io, writer, id, connection);
                }
            } else {
                try sendResponse(writer, 404, "text/plain", "Not found", connection);
            }
        }

        if (body_owned) state.allocator.free(body);
        try writer_obj.interface.flush();
        if (!keep_alive or request_error) return;
    }
}

fn cleanupThread(io: Io) !void {
    const cwd = std.Io.Dir.cwd();
    while (true) {
        io.sleep(Io.Duration.fromSeconds(60), .real) catch {};

        const now = nowSecs(io);
        var dir = cwd.openDir(io, DATA_DIR, .{ .iterate = true }) catch continue;
        defer dir.close(io);

        var it = dir.iterate();
        while (true) {
            const entry = it.next(io) catch break;
            const e = entry orelse break;
            if (e.kind != .file) continue;
            if (!std.mem.endsWith(u8, e.name, ".json")) continue;

            const meta_path = std.fmt.allocPrint(state.allocator, "{s}/{s}", .{ DATA_DIR, e.name }) catch continue;
            const data = cwd.readFileAlloc(io, meta_path, state.allocator, .limited(4096)) catch {
                state.allocator.free(meta_path);
                continue;
            };

            const created_at = jsonFieldInt(data, "created_at") orelse {
                state.allocator.free(data);
                state.allocator.free(meta_path);
                continue;
            };
            const ttl_seconds = jsonFieldInt(data, "ttl_seconds") orelse {
                state.allocator.free(data);
                state.allocator.free(meta_path);
                continue;
            };

            state.allocator.free(data);
            if (now > created_at + @as(i64, @intCast(ttl_seconds))) {
                cwd.deleteFile(io, meta_path) catch {};
            }
            state.allocator.free(meta_path);
        }
    }
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.gpa;

    state = try ServerState.init(allocator, io);
    defer state.deinit();

    const args = try init.minimal.args.toSlice(allocator);
    defer allocator.free(args);

    const port: u16 = if (args.len > 1) std.fmt.parseInt(u16, args[1], 10) catch 8080 else 8080;

    const addr = try net.IpAddress.parseIp4("0.0.0.0", port);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);

    std.log.info("zig-link listening on http://0.0.0.0:{d}", .{port});

    const cleanup_handle = try std.Thread.spawn(.{}, cleanupThread, .{io});
    cleanup_handle.detach();

    while (true) {
        const stream = try server.accept(io);
        const client_addr = stream.socket.address;

        const thread = std.Thread.spawn(.{}, handleConnection, .{ io, stream, client_addr }) catch |err| {
            std.log.err("Spawn error: {}", .{err});
            stream.close(io);
            continue;
        };
        thread.detach();
    }
}