const clap = @import("clap");
const codesign = @import("codesign.zig");

const std = @import("std");
const io = std.io;

var gpa_alloc = std.heap.GeneralPurposeAllocator(.{}){};
const gpa = gpa_alloc.allocator();

pub fn main() !void {
    const stderr = io.getStdErr().writer();

    const params = comptime [_]clap.Param(clap.Help){
        clap.parseParam("-h, --help                   Display this help and exit.") catch unreachable,
        clap.parseParam("-e, --entitlements <PATH>    Specify path to entitlements file for embedding.") catch unreachable,
        clap.parseParam("-s, --sign <PATH>            Specify path to signing identity.") catch unreachable,
        clap.parseParam("<PATH>") catch unreachable,
    };

    const parsers = comptime .{
        .PATH = clap.parsers.string,
    };

    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, parsers, .{
        .diagnostic = &diag,
    }) catch |err| {
        diag.report(stderr, err) catch {};
        return err;
    };
    defer res.deinit();

    if (res.args.help) {
        return clap.help(stderr, clap.Help, &params, .{});
    }

    try codesign.signApp(gpa, res.positionals[0], .{
        .identity = res.args.sign,
        .entitlements = res.args.entitlements,
    });
}
