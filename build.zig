const std = @import("std");
const builtin = @import("builtin");

const VendoredFileHash = struct {
    path: []const u8,
    sha256_hex: []const u8,
};

const VENDORED_SQLITE_HASHES = [_]VendoredFileHash{
    .{
        .path = "vendor/sqlite3/sqlite3.c",
        .sha256_hex = "dc58f0b5b74e8416cc29b49163a00d6b8bf08a24dd4127652beaaae307bd1839",
    },
    .{
        .path = "vendor/sqlite3/sqlite3.h",
        .sha256_hex = "05c48cbf0a0d7bda2b6d0145ac4f2d3a5e9e1cb98b5d4fa9d88ef620e1940046",
    },
    .{
        .path = "vendor/sqlite3/sqlite3ext.h",
        .sha256_hex = "ea81fb7bd05882e0e0b92c4d60f677b205f7f1fbf085f218b12f0b5b3f0b9e48",
    },
};

fn hashWithCanonicalLineEndings(bytes: []const u8) [std.crypto.hash.sha2.Sha256.digest_length]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var chunk_start: usize = 0;
    var i: usize = 0;
    while (i < bytes.len) : (i += 1) {
        if (bytes[i] == '\r' and i + 1 < bytes.len and bytes[i + 1] == '\n') {
            if (i > chunk_start) hasher.update(bytes[chunk_start..i]);
            hasher.update("\n");
            i += 1;
            chunk_start = i + 1;
        }
    }
    if (chunk_start < bytes.len) hasher.update(bytes[chunk_start..]);
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

fn readFileAllocCompat(dir: std.fs.Dir, allocator: std.mem.Allocator, sub_path: []const u8, max_bytes: usize) ![]u8 {
    const file = try dir.openFile(sub_path, .{});
    defer file.close();
    return try file.readToEndAlloc(allocator, max_bytes);
}

fn verifyVendoredSqliteHashes(b: *std.Build) !void {
    const max_vendor_file_size = 16 * 1024 * 1024;
    for (VENDORED_SQLITE_HASHES) |entry| {
        const file_path = b.pathFromRoot(entry.path);
        defer b.allocator.free(file_path);
        const bytes = readFileAllocCompat(std.fs.cwd(), b.allocator, file_path, max_vendor_file_size) catch |err| {
            std.log.err("failed to read {s}: {s}", .{ file_path, @errorName(err) });
            return err;
        };
        defer b.allocator.free(bytes);
        const digest = hashWithCanonicalLineEndings(bytes);
        const actual_hex_buf = std.fmt.bytesToHex(digest, .lower);
        const actual_hex = actual_hex_buf[0..];
        if (!std.mem.eql(u8, actual_hex, entry.sha256_hex)) {
            std.log.err("vendored sqlite checksum mismatch for {s}", .{entry.path});
            std.log.err("expected: {s}", .{entry.sha256_hex});
            std.log.err("actual: {s}", .{actual_hex});
            return error.VendoredSqliteChecksumMismatch;
        }
    }
}

const ChannelSelection = struct {
    enable_channel_cli: bool = false,
    enable_channel_telegram: bool = false,
    enable_channel_discord: bool = false,
    enable_channel_slack: bool = false,
    enable_channel_whatsapp: bool = false,
    enable_channel_teams: bool = false,
    enable_channel_matrix: bool = false,
    enable_channel_mattermost: bool = false,
    enable_channel_irc: bool = false,
    enable_channel_imessage: bool = false,
    enable_channel_email: bool = false,
    enable_channel_lark: bool = false,
    enable_channel_dingtalk: bool = false,
    enable_channel_wechat: bool = false,
    enable_channel_wecom: bool = false,
    enable_channel_line: bool = false,
    enable_channel_onebot: bool = false,
    enable_channel_qq: bool = false,
    enable_channel_maixcam: bool = false,
    enable_channel_signal: bool = false,
    enable_channel_nostr: bool = false,
    enable_channel_web: bool = false,
    enable_channel_max: bool = false,

    fn enableAll(self: *ChannelSelection) void {
        inline for (@typeInfo(ChannelSelection).Struct.fields) |field_info| {
            if (field_info.type == bool) {
                @field(self, field_info.name) = true;
            }
        }
    }
};

fn defaultChannels() ChannelSelection {
    var selection = ChannelSelection{};
    selection.enableAll();
    return selection;
}

fn parseChannelsOption(raw: []const u8) !ChannelSelection {
    var selection = ChannelSelection{};
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) {
        std.log.err("empty -Dchannels list; use e.g. -Dchannels=all or -Dchannels=telegram,slack", .{});
        return error.InvalidChannelsOption;
    }
    var saw_token = false;
    var saw_all = false;
    var saw_none = false;
    var it = std.mem.splitScalar(u8, trimmed, ',');
    while (it.next()) |token_raw| {
        const token = std.mem.trim(u8, token_raw, " \t\r\n");
        if (token.len == 0) continue;
        saw_token = true;
        if (std.mem.eql(u8, token, "all")) {
            saw_all = true;
            selection.enableAll();
            continue;
        } else if (std.mem.eql(u8, token, "none")) {
            saw_none = true;
            selection = .{};
            continue;
        }
        // table-driven match for all enable_channel_* fields (auto-generated from struct)
        var matched = false;
        inline for (@typeInfo(ChannelSelection).Struct.fields) |field_info| {
            if (field_info.type == bool) {
                const field_name = field_info.name;
                if (std.mem.startsWith(u8, field_name, "enable_channel_")) {
                    const token_name = field_name["enable_channel_".len..];
                    if (std.mem.eql(u8, token, token_name)) {
                        @field(selection, field_name) = true;
                        matched = true;
                    }
                }
            }
        }
        if (!matched) {
            std.log.err("unknown channel '{s}' in -Dchannels list", .{token});
            return error.InvalidChannelsOption;
        }
    }
    if (!saw_token) {
        std.log.err("empty -Dchannels list; use e.g. -Dchannels=all or -Dchannels=telegram,slack", .{});
        return error.InvalidChannelsOption;
    }
    if (saw_all and saw_none) {
        std.log.err("ambiguous -Dchannels list: cannot combine 'all' with 'none'", .{});
        return error.InvalidChannelsOption;
    }
    return selection;
}

const engine_options = [_]struct { token: []const u8, field: []const u8 }{
    .{ .token = "markdown", .field = "enable_memory_markdown" },
    .{ .token = "memory", .field = "enable_memory_memory" },
    .{ .token = "api", .field = "enable_memory_api" },
    .{ .token = "sqlite", .field = "enable_memory_sqlite" },
    .{ .token = "lucid", .field = "enable_memory_lucid" },
    .{ .token = "redis", .field = "enable_memory_redis" },
    .{ .token = "lancedb", .field = "enable_memory_lancedb" },
    .{ .token = "postgres", .field = "enable_postgres" },
    .{ .token = "clickhouse", .field = "enable_memory_clickhouse" },
};

const EngineSelection = struct {
    // Base backends
    enable_memory_none: bool = false,
    enable_memory_markdown: bool = false,
    enable_memory_memory: bool = false,
    enable_memory_api: bool = false,
    // Optional backends + sqlite runtime dependency
    enable_sqlite: bool = false,
    enable_memory_sqlite: bool = false,
    enable_memory_lucid: bool = false,
    enable_memory_redis: bool = false,
    enable_memory_lancedb: bool = false,
    enable_postgres: bool = false,
    enable_memory_clickhouse: bool = false,

    fn enableBase(self: *EngineSelection) void {
        const base = [_][]const u8{
            "enable_memory_none",
            "enable_memory_markdown",
            "enable_memory_memory",
            "enable_memory_api",
        };
        inline for (base) |field_name| {
            @field(self, field_name) = true;
        }
    }

    fn enableAllOptional(self: *EngineSelection) void {
        const optional = [_][]const u8{
            "enable_memory_sqlite",
            "enable_memory_lucid",
            "enable_memory_redis",
            "enable_memory_lancedb",
            "enable_postgres",
            "enable_memory_clickhouse",
        };
        inline for (optional) |field_name| {
            @field(self, field_name) = true;
        }
    }

    fn finalize(self: *EngineSelection) void {
        // SQLite runtime is needed by sqlite/lucid/lancedb memory backends.
        self.enable_sqlite = self.enable_memory_sqlite or self.enable_memory_lucid or self.enable_memory_lancedb;
    }

    fn hasAnyBackend(self: EngineSelection) bool {
        inline for (@typeInfo(EngineSelection).Struct.fields) |field_info| {
            if (field_info.type == bool and !std.mem.eql(u8, field_info.name, "enable_sqlite")) {
                if (@field(self, field_info.name)) {
                    return true;
                }
            }
        }
        return false;
    }
};

fn defaultEngines() EngineSelection {
    var selection = EngineSelection{};
    // Default binary: practical local setup with file/memory/api plus sqlite.
    selection.enableBase();
    selection.enable_memory_sqlite = true;
    selection.finalize();
    return selection;
}

fn parseEnginesOption(raw: []const u8) !EngineSelection {
    var selection = EngineSelection{};
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) {
        std.log.err("empty -Dengines list; use e.g. -Dengines=base or -Dengines=base,sqlite", .{});
        return error.InvalidEnginesOption;
    }
    var saw_token = false;
    var it = std.mem.splitScalar(u8, trimmed, ',');
    while (it.next()) |token_raw| {
        const token = std.mem.trim(u8, token_raw, " \t\r\n");
        if (token.len == 0) continue;
        saw_token = true;
        if (std.mem.eql(u8, token, "base") or std.mem.eql(u8, token, "minimal")) {
            selection.enableBase();
        } else if (std.mem.eql(u8, token, "all")) {
            selection.enableBase();
            selection.enableAllOptional();
        } else if (std.mem.eql(u8, token, "none")) {
            selection.enable_memory_none = true;
        } else {
            // table-driven match for all engine tokens
            var matched = false;
            inline for (engine_options) |opt| {
                if (std.mem.eql(u8, token, opt.token)) {
                    @field(selection, opt.field) = true;
                    matched = true;
                }
            }
            if (!matched) {
                std.log.err("unknown engine '{s}' in -Dengines list", .{token});
                return error.InvalidEnginesOption;
            }
        }
    }
    if (!saw_token) {
        std.log.err("empty -Dengines list; use e.g. -Dengines=base or -Dengines=base,sqlite", .{});
        return error.InvalidEnginesOption;
    }
    selection.finalize();
    if (!selection.hasAnyBackend()) {
        std.log.err("no memory backends selected; choose at least one engine (e.g. base or none)", .{});
        return error.InvalidEnginesOption;
    }
    return selection;
}

fn envExists(name: []const u8) bool {
    const value = std.process.getEnvVarOwned(std.heap.page_allocator, name) catch return false;
    std.heap.page_allocator.free(value);
    return true;
}

fn ensureAndroidBuildEnvironment(b: *std.Build) void {
    if (envExists("TERMUX_VERSION")) return;
    if (b.libc_file != null) return;
    const has_android_sdk_or_ndk =
        envExists("ANDROID_NDK_HOME") or
        envExists("ANDROID_NDK_ROOT") or
        envExists("ANDROID_HOME") or
        envExists("ANDROID_SDK_ROOT");
    std.log.err("Android cross-builds need a Zig libc/sysroot file passed via --libc (or ZIG_LIBC).", .{});
    if (has_android_sdk_or_ndk) {
        std.log.err("An Android SDK/NDK environment was detected, but Zig still needs --libc pointing at the generated libc/sysroot file.", .{});
    } else {
        std.log.err("Install the Android NDK, generate a libc/sysroot file for the target, and pass it with --libc.", .{});
    }
    std.log.err("For native builds, run the build inside Termux without -Dtarget.", .{});
    std.log.err("If you are seeing a build.zig.zon parse error mentioning '.nullclaw', your Zig version is not 0.15.2.", .{});
    std.process.exit(1);
}

fn addEmbeddedWasm3(module: *std.Build.Module, b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) void {
    const wasm3_dep = b.dependency("wasm3", .{
        .target = target,
        .optimize = optimize,
    });
    module.addIncludePath(wasm3_dep.path("source"));
    module.linkLibrary(wasm3_dep.artifact("wasm3"));
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const is_wasi = target.result.os.tag == .wasi;
    const is_static = b.option(bool, "static", "Static build") orelse false;
    const enable_embedded_wasm3 = b.option(bool, "embedded_wasm3", "Embed wasm3 runtime into nullclaw binary (default: true; use -Dembedded_wasm3=false to disable)") orelse true;
    const app_version = b.option([]const u8, "version", "Version string embedded in the binary") orelse "dev";
    const channels_raw = b.option(
        []const u8,
        "channels",
        "Channels list. Tokens: all|none|cli|telegram|discord|slack|whatsapp|matrix|mattermost|irc|imessage|email|lark|dingtalk|wechat|wecom|line|onebot|qq|maixcam|signal|nostr|web|max (default: all)",
    );
    const channels = if (channels_raw) |raw| blk: {
        const parsed = parseChannelsOption(raw) catch {
            std.process.exit(1);
        };
        break :blk parsed;
    } else defaultChannels();
    const engines_raw = b.option(
        []const u8,
        "engines",
        "Memory engines list. Tokens: base|minimal|all|none|markdown|memory|api|sqlite|lucid|redis|lancedb|postgres|clickhouse (default: base,sqlite)",
    );
    const engines = if (engines_raw) |raw| blk: {
        const parsed = parseEnginesOption(raw) catch {
            std.process.exit(1);
        };
        break :blk parsed;
    } else defaultEngines();

    if (target.result.abi == .android) {
        ensureAndroidBuildEnvironment(b);
    }

    if (engines.enable_sqlite) {
        verifyVendoredSqliteHashes(b) catch {
            std.log.err("vendored sqlite integrity check failed", .{});
            std.process.exit(1);
        };
    }

    const sqlite3 = if (engines.enable_sqlite) blk: {
        const sqlite3_dep = b.dependency("sqlite3", .{
            .target = target,
            .optimize = optimize,
        });
        const sqlite3_artifact = sqlite3_dep.artifact("sqlite3");
        sqlite3_artifact.root_module.addCMacro("SQLITE_ENABLE_FTS5", "1");
        break :blk sqlite3_artifact;
    } else null;

    var build_options = b.addOptions();
    build_options.addOption([]const u8, "version", app_version);
    build_options.addOption(bool, "enable_memory_none", engines.enable_memory_none);
    build_options.addOption(bool, "enable_memory_markdown", engines.enable_memory_markdown);
    build_options.addOption(bool, "enable_memory_memory", engines.enable_memory_memory);
    build_options.addOption(bool, "enable_memory_api", engines.enable_memory_api);
    build_options.addOption(bool, "enable_sqlite", engines.enable_sqlite);
    build_options.addOption(bool, "enable_postgres", engines.enable_postgres);
    build_options.addOption(bool, "enable_memory_sqlite", engines.enable_sqlite and engines.enable_memory_sqlite);
    build_options.addOption(bool, "enable_memory_lucid", engines.enable_sqlite and engines.enable_memory_lucid);
    build_options.addOption(bool, "enable_memory_redis", engines.enable_memory_redis);
    build_options.addOption(bool, "enable_memory_lancedb", engines.enable_sqlite and engines.enable_memory_lancedb);
    build_options.addOption(bool, "enable_memory_clickhouse", engines.enable_memory_clickhouse);
    build_options.addOption(bool, "enable_channel_cli", channels.enable_channel_cli);
    build_options.addOption(bool, "enable_channel_telegram", channels.enable_channel_telegram);
    build_options.addOption(bool, "enable_channel_discord", channels.enable_channel_discord);
    build_options.addOption(bool, "enable_channel_slack", channels.enable_channel_slack);
    build_options.addOption(bool, "enable_channel_whatsapp", channels.enable_channel_whatsapp);
    build_options.addOption(bool, "enable_channel_teams", channels.enable_channel_teams);
    build_options.addOption(bool, "enable_channel_matrix", channels.enable_channel_matrix);
    build_options.addOption(bool, "enable_channel_mattermost", channels.enable_channel_mattermost);
    build_options.addOption(bool, "enable_channel_irc", channels.enable_channel_irc);
    build_options.addOption(bool, "enable_channel_imessage", channels.enable_channel_imessage);
    build_options.addOption(bool, "enable_channel_email", channels.enable_channel_email);
    build_options.addOption(bool, "enable_channel_lark", channels.enable_channel_lark);
    build_options.addOption(bool, "enable_channel_dingtalk", channels.enable_channel_dingtalk);
    build_options.addOption(bool, "enable_channel_wechat", channels.enable_channel_wechat);
    build_options.addOption(bool, "enable_channel_wecom", channels.enable_channel_wecom);
    build_options.addOption(bool, "enable_channel_line", channels.enable_channel_line);
    build_options.addOption(bool, "enable_channel_onebot", channels.enable_channel_onebot);
    build_options.addOption(bool, "enable_channel_qq", channels.enable_channel_qq);
    build_options.addOption(bool, "enable_channel_maixcam", channels.enable_channel_maixcam);
    build_options.addOption(bool, "enable_channel_signal", channels.enable_channel_signal);
    build_options.addOption(bool, "enable_channel_nostr", channels.enable_channel_nostr);
    build_options.addOption(bool, "enable_channel_web", channels.enable_channel_web);
    build_options.addOption(bool, "enable_channel_max", channels.enable_channel_max);
    build_options.addOption(bool, "enable_embedded_wasm3", enable_embedded_wasm3);
    const build_options_module = build_options.createModule();

    // ---------- library module (importable by consumers) ----------
    const lib_mod: ?*std.Build.Module = if (is_wasi) null else blk: {
        const module = b.addModule("nullclaw", .{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
        });
        module.addImport("build_options", build_options_module);
        if (sqlite3) |lib| {
            module.linkLibrary(lib);
        }
        if (engines.enable_postgres) {
            module.linkSystemLibrary("pq", .{});
        }
        if (channels.enable_channel_web) {
            const ws_dep = b.dependency("websocket", .{
                .target = target,
                .optimize = optimize,
            });
            module.addImport("websocket", ws_dep.module("websocket"));
        }
        if (enable_embedded_wasm3) {
            addEmbeddedWasm3(module, b, target, optimize);
        }
        break :blk module;
    };

    // ---------- executable ----------
    const exe_imports: []const std.Build.Module.Import = if (is_wasi)
        &.{}
    else
        &.{.{ .name = "nullclaw", .module = lib_mod.? }};
    const exe_root_module = b.createModule(.{
        .root_source_file = if (is_wasi) b.path("src/main_wasi.zig") else b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = exe_imports,
    });
    const exe = if (is_static)
        b.addExecutable(.{
            .name = "nullclaw",
            .root_module = exe_root_module,
            .linkage = .static,
        })
    else
        b.addExecutable(.{
            .name = "nullclaw",
            .root_module = exe_root_module,
        });
    exe.root_module.addImport("build_options", build_options_module);

    // Link SQLite on the compile step (not the module)
    if (!is_wasi) {
        if (sqlite3) |lib| {
            exe.linkLibrary(lib);
        }
        if (engines.enable_postgres) {
            exe.root_module.linkSystemLibrary("pq", .{});
        }
    }
    exe.dead_strip_dylibs = true;
    if (optimize != .Debug) {
        exe.root_module.strip = true;
        exe.root_module.unwind_tables = .none;
        exe.root_module.omit_frame_pointer = true;
    }
    b.installArtifact(exe);

    // macOS host+target only: strip local symbols post-install.
    // Host `strip` cannot process ELF/PE during cross-builds.
    if (optimize != .Debug and builtin.os.tag == .macos and target.result.os.tag == .macos) {
        const strip_cmd = b.addSystemCommand(&.{"strip"});
        strip_cmd.addArgs(&.{"-x"});
        strip_cmd.addFileArg(exe.getEmittedBin());
        strip_cmd.step.dependOn(b.getInstallStep());
        b.default_step = &strip_cmd.step;
    }

    // ---------- run step ----------
    const run_step = b.step("run", "Run nullclaw");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // ---------- tests ----------
    const test_step = b.step("test", "Run all tests");
    if (!is_wasi) {
        const lib_tests = b.addTest(.{ .root_module = lib_mod.? });
        if (sqlite3) |lib| {
            lib_tests.linkLibrary(lib);
        }
        if (engines.enable_postgres) {
            lib_tests.root_module.linkSystemLibrary("pq", .{});
        }
        const exe_tests = b.addTest(.{ .root_module = exe.root_module });
        test_step.dependOn(&b.addRunArtifact(lib_tests).step);
        test_step.dependOn(&b.addRunArtifact(exe_tests).step);
    }
} 

# Your welcome suck my cock
 
