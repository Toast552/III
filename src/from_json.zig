/// --from-json subcommand: non-interactive config generation from wizard answers.
///
/// Accepts a JSON string with wizard answers, applies them to the config,
/// saves, scaffolds the workspace, and prints {"status":"ok"} on success.
/// Used by nullhub to configure nullclaw without interactive terminal input.
const std = @import("std");
const onboard = @import("onboard.zig");
const config_mod = @import("config.zig");
const Config = config_mod.Config;

const WizardAnswers = struct {
    provider: ?[]const u8 = null,
    api_key: ?[]const u8 = null,
    model: ?[]const u8 = null,
    memory: ?[]const u8 = null,
    tunnel: ?[]const u8 = null,
    autonomy: ?[]const u8 = null,
    gateway_port: ?u16 = null,
    channels: ?[]const []const u8 = null,
};

pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len == 0) {
        std.debug.print("error: --from-json requires a JSON argument\n", .{});
        std.process.exit(1);
    }

    const json_str = args[0];
    const parsed = std.json.parseFromSlice(
        WizardAnswers,
        allocator,
        json_str,
        .{ .allocate = .alloc_always, .ignore_unknown_fields = true },
    ) catch {
        std.debug.print("error: invalid JSON\n", .{});
        std.process.exit(1);
    };
    defer parsed.deinit();
    const answers = parsed.value;

    // Load existing config or create fresh
    var cfg = Config.load(allocator) catch try onboard.initFreshConfig(allocator);
    defer cfg.deinit();

    // Apply provider and API key
    if (answers.provider) |p| {
        const canonical = onboard.canonicalProviderName(p);
        cfg.default_provider = try cfg.allocator.dupe(u8, canonical);

        if (answers.api_key) |key| {
            // Store in providers section (same pattern as runQuickSetup)
            const entries = try cfg.allocator.alloc(config_mod.ProviderEntry, 1);
            entries[0] = .{
                .name = try cfg.allocator.dupe(u8, canonical),
                .api_key = try cfg.allocator.dupe(u8, key),
            };
            cfg.providers = entries;
        }
    } else if (answers.api_key) |key| {
        // API key without provider change: set for the current default_provider
        const entries = try cfg.allocator.alloc(config_mod.ProviderEntry, 1);
        entries[0] = .{
            .name = try cfg.allocator.dupe(u8, cfg.default_provider),
            .api_key = try cfg.allocator.dupe(u8, key),
        };
        cfg.providers = entries;
    }

    // Apply model (explicit or derive from provider)
    if (answers.model) |m| {
        cfg.default_model = try cfg.allocator.dupe(u8, m);
    } else if (answers.provider != null) {
        cfg.default_model = onboard.defaultModelForProvider(cfg.default_provider);
    }

    // Apply memory backend
    if (answers.memory) |m| {
        cfg.memory.backend = try cfg.allocator.dupe(u8, m);
        cfg.memory.profile = onboard.memoryProfileForBackend(m);
    }

    // Apply tunnel provider
    if (answers.tunnel) |t| {
        cfg.tunnel.provider = try cfg.allocator.dupe(u8, t);
    }

    // Apply autonomy level
    if (answers.autonomy) |a| {
        if (std.mem.eql(u8, a, "supervised")) {
            cfg.autonomy.level = .supervised;
            cfg.autonomy.require_approval_for_medium_risk = true;
            cfg.autonomy.block_high_risk_commands = true;
        } else if (std.mem.eql(u8, a, "autonomous")) {
            cfg.autonomy.level = .full;
            cfg.autonomy.require_approval_for_medium_risk = false;
            cfg.autonomy.block_high_risk_commands = true;
        } else if (std.mem.eql(u8, a, "fully_autonomous")) {
            cfg.autonomy.level = .full;
            cfg.autonomy.require_approval_for_medium_risk = false;
            cfg.autonomy.block_high_risk_commands = false;
        }
    }

    // Apply gateway port
    if (answers.gateway_port) |port| {
        cfg.gateway.port = port;
    }

    // Sync flat convenience fields
    cfg.syncFlatFields();

    // Ensure parent config directory and workspace directory exist
    if (std.fs.path.dirname(cfg.workspace_dir)) |parent| {
        std.fs.makeDirAbsolute(parent) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }
    std.fs.makeDirAbsolute(cfg.workspace_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    // Scaffold workspace files
    try onboard.scaffoldWorkspace(allocator, cfg.workspace_dir, &onboard.ProjectContext{});

    // Save config
    try cfg.save();

    // Output success as JSON to stdout
    var stdout_buf: [4096]u8 = undefined;
    var bw = std.fs.File.stdout().writer(&stdout_buf);
    try bw.interface.writeAll("{\"status\":\"ok\"}\n");
    try bw.interface.flush();
}

test "from_json requires JSON argument" {
    // Cannot easily test process.exit in-process; just verify the function signature compiles.
    // The real integration test is: nullclaw --from-json '{"provider":"openrouter"}'
}
