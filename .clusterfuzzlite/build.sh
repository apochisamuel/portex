#!/bin/bash -eu
cd "$SRC"

ln -sf ../src fuzz/src

compile_zig_fuzzer fuzz/parse_fuzzer.zig parse_fuzzer
compile_zig_fuzzer fuzz/import_fuzzer.zig import_fuzzer
compile_zig_fuzzer fuzz/resource_fuzzer.zig resource_fuzzer
