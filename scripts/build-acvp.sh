#!/usr/bin/env bash
#
# build-acvp.sh — download NIST ACVP test vectors for ML-KEM-768 and
# regenerate tests/acvp_ml_kem_vectors.zig.
#
# These are the canonical FIPS-203 known-answer tests published by NIST
# at https://github.com/usnistgov/ACVP-Server. They validate the
# *primitive* (ML-KEM-768 keygen / encaps / decaps), independently of
# our protocol layer or any other PQNoise implementation. If Zig stdlib
# ever ships a regression in its FIPS-203 implementation, these tests
# fire immediately.
#
# What is and isn't checked in:
#   ✔ this script
#   ✔ scripts/acvp/convert.py (the JSON → Zig converter)
#   ✔ tests/acvp_ml_kem_vectors.zig (the generated battery)
#   ✗ scripts/acvp/raw/ (downloaded JSON; large, regenerable)
#
# Re-run only when bumping to a newer ACVP test set or when NIST
# publishes additional vectors.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
acvp_dir="$repo_root/scripts/acvp"
raw_dir="$acvp_dir/raw"
out_path="$repo_root/tests/acvp_ml_kem_vectors.zig"

base_url="https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files"

ensure_python() {
    if ! command -v python3 >/dev/null 2>&1; then
        echo "==> ERROR: python3 is required but not on PATH." >&2
        exit 1
    fi
}

download() {
    local subpath="$1"
    local dest="$raw_dir/$(echo "$subpath" | tr '/' '_')"
    if [[ -f "$dest" ]]; then
        echo "==> $dest already present (skip)"
        return
    fi
    echo "==> Downloading $subpath"
    curl -sSfL "$base_url/$subpath" -o "$dest"
}

main() {
    ensure_python
    mkdir -p "$raw_dir"
    download "ML-KEM-keyGen-FIPS203/prompt.json"
    download "ML-KEM-keyGen-FIPS203/expectedResults.json"
    download "ML-KEM-encapDecap-FIPS203/prompt.json"
    download "ML-KEM-encapDecap-FIPS203/expectedResults.json"

    echo "==> Converting to $out_path"
    python3 "$acvp_dir/convert.py" \
        --keygen-prompt   "$raw_dir/ML-KEM-keyGen-FIPS203_prompt.json" \
        --keygen-expected "$raw_dir/ML-KEM-keyGen-FIPS203_expectedResults.json" \
        --encap-prompt    "$raw_dir/ML-KEM-encapDecap-FIPS203_prompt.json" \
        --encap-expected  "$raw_dir/ML-KEM-encapDecap-FIPS203_expectedResults.json" \
        --parameter-set   "ML-KEM-768" \
        --output          "$out_path"
    echo "==> Done. tests/acvp_ml_kem_vectors.zig regenerated."
    echo "    Run 'zig build test-kats' to verify our impl against it."
}

main "$@"
