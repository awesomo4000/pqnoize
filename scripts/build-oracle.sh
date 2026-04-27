#!/usr/bin/env bash
#
# build-oracle.sh — build the clatter-based oracle and regenerate
# tests/oracle_vectors.zig from it.
#
# This script bootstraps a project-local Rust toolchain (so it doesn't
# pollute the user's shell), pulls clatter via cargo, builds the harness
# under scripts/oracle/, runs it, and writes the generated Zig source
# back into the repo at tests/oracle_vectors.zig.
#
# What is and isn't checked in:
#   ✔ this script
#   ✔ scripts/oracle/{Cargo.toml,Cargo.lock,rust-toolchain.toml,src/}
#   ✔ tests/oracle_vectors.zig (the generated battery)
#   ✗ scripts/oracle/target/ (build artifacts)
#   ✗ scripts/.toolchain/ (project-local rustup install)
#   ✗ ~/.cargo or ~/.rustup pollution (we point CARGO_HOME / RUSTUP_HOME
#     at the project-local dir so nothing leaks into the user's setup)
#
# Re-run any time clatter is bumped or the harness is changed. The Zig
# tests then verify our implementation against the new battery.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
oracle_dir="$repo_root/scripts/oracle"
out_path="$repo_root/tests/oracle_vectors.zig"
toolchain_dir="$repo_root/scripts/.toolchain"

export RUSTUP_HOME="$toolchain_dir/rustup"
export CARGO_HOME="$toolchain_dir/cargo"
export PATH="$CARGO_HOME/bin:$PATH"

required_rust_version=$(grep -oE 'channel = "[^"]+"' "$oracle_dir/rust-toolchain.toml" | sed 's/channel = "\(.*\)"/\1/')

ensure_rustup() {
    if command -v rustup >/dev/null 2>&1 && [[ -d "$RUSTUP_HOME" ]]; then
        return
    fi
    echo "==> Installing project-local rustup into $toolchain_dir"
    mkdir -p "$toolchain_dir"
    # Install rustup non-interactively, no shell modifications, default profile.
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --no-modify-path --default-toolchain none
}

ensure_toolchain() {
    if rustup toolchain list 2>/dev/null | grep -q "^$required_rust_version"; then
        return
    fi
    echo "==> Installing Rust toolchain $required_rust_version"
    rustup toolchain install "$required_rust_version" --profile minimal
}

build_harness() {
    echo "==> Building oracle harness"
    (cd "$oracle_dir" && cargo build --release --quiet)
}

run_harness() {
    echo "==> Generating $out_path"
    (cd "$oracle_dir" && cargo run --release --quiet) > "$out_path"
}

main() {
    ensure_rustup
    ensure_toolchain
    build_harness
    run_harness
    echo "==> Done. tests/oracle_vectors.zig regenerated."
    echo "    Run 'zig build test-kats' to verify our impl against it."
}

main "$@"
