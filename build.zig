const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Library
    const lib = b.addStaticLibrary(.{
        .name = "portex",
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(lib);

    // Fuzzers
    const fuzzers = [_][]const u8{ "parse_fuzz", "import_fuzz", "resource_fuzz" };
    for (fuzzers) |name| {
        const exe = b.addExecutable(.{
            .name = name,
            .root_source_file = b.path(b.fmt("fuzz/{s}.zig", .{name})),
            .target = target,
            .optimize = optimize,
        });
        exe.linkLibC();
        b.installArtifact(exe);
    }

    // Tests
    const tests = b.addTest(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
}
