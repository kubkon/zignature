const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{});

    const lib = b.addStaticLibrary("zig-codesign", "src/codesign.zig");
    lib.setTarget(target);
    lib.setBuildMode(mode);
    lib.addPackagePath("ZigKit", "ZigKit/src/main.zig");
    lib.install();

    const exe = b.addExecutable("zig-codesign", "src/main.zig");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.addPackagePath("clap", "clap/clap.zig");
    exe.addPackagePath("ZigKit", "ZigKit/src/main.zig");
    exe.linkFramework("CoreFoundation");
    exe.linkFramework("Security");
    exe.install();

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const main_tests = b.addTest("src/codesign.zig");
    main_tests.setTarget(target);
    main_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);
}
