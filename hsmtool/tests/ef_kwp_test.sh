#!/usr/bin/env bash
#
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
source hsmtool/tests/test_lib.sh

MODULE="$1"
TEST_DIR="$(mktemp -d)"
trap 'rm -rf "${TEST_DIR}"' EXIT

INPUT_PAYLOAD="${TEST_DIR}/secret_payload.bin"
WRAPPED_ENVELOPE="${TEST_DIR}/envelope.kwp"
RESTORED_PAYLOAD="${TEST_DIR}/restored_payload.bin"

# Generate 48 bytes of arbitrary binary secret data
head -c 48 /dev/urandom > "${INPUT_PAYLOAD}"

echo "=== 1. Generate AES-256 Wrapping Key on Token ==="
${HSMTOOL} --module "${MODULE}" aes generate --label test-wrapping-key

echo "=== 2. Write Original Elementary File to Token ==="
${HSMTOOL} --module "${MODULE}" object write \
    --label test-ef \
    --application "test-app-id" \
    --private \
    "${INPUT_PAYLOAD}"

echo "=== 3. Export Elementary File via Hardware KWP ==="
${HSMTOOL} --module "${MODULE}" ef export \
    --label test-ef \
    --wrapping-key test-wrapping-key \
    "${WRAPPED_ENVELOPE}"

# Verify the exported file is not empty and is aligned to 8 bytes (>= 16 bytes)
ENVELOPE_SIZE=$(wc -c < "${WRAPPED_ENVELOPE}")
if [[ $(( ENVELOPE_SIZE % 8 )) -ne 0 || "${ENVELOPE_SIZE}" -lt 16 ]]; then
    echo "Error: Exported KWP envelope size ${ENVELOPE_SIZE} is invalid" >&2
    exit 1
fi
echo "Exported KWP envelope size: ${ENVELOPE_SIZE} bytes"

echo "=== 4. Test Overwrite / Collision Protection ==="
# Attempting import while 'test-ef' already exists MUST fail
if ${HSMTOOL} --module "${MODULE}" ef import \
    --wrapping-key test-wrapping-key \
    "${WRAPPED_ENVELOPE}" 2>/dev/null; then
    echo "Error: Import should have failed due to existing object collision" >&2
    exit 1
fi
echo "Collision protection successfully prevented overwrite."

echo "=== 5. Destroy Original Elementary File ==="
${HSMTOOL} --module "${MODULE}" object destroy --label test-ef

echo "=== 6. Import Elementary File via Hardware KWP ==="
# Note: user does NOT provide --label or --application; they are recovered from authenticated metadata
${HSMTOOL} --module "${MODULE}" ef import \
    --wrapping-key test-wrapping-key \
    "${WRAPPED_ENVELOPE}"

echo "=== 7. Read Back and Verify 100% Bit-for-Bit Identity ==="
${HSMTOOL} --module "${MODULE}" object read \
    --label test-ef \
    "${RESTORED_PAYLOAD}"

cmp "${INPUT_PAYLOAD}" "${RESTORED_PAYLOAD}"
echo "Payload verified: restored data is bit-for-bit identical to original!"

echo "=== 8. Test Tamper Rejection ==="
# Flip a byte in the middle of the envelope
TAMPERED_ENVELOPE="${TEST_DIR}/tampered.kwp"
cp "${WRAPPED_ENVELOPE}" "${TAMPERED_ENVELOPE}"
# Flip byte 12
python3 -c "
with open('${TAMPERED_ENVELOPE}', 'r+b') as f:
    f.seek(12)
    b = f.read(1)
    f.seek(12)
    f.write(bytes([b[0] ^ 0x01]))
"

# Destroy existing object so collision won't trigger first
${HSMTOOL} --module "${MODULE}" object destroy --label test-ef

# Import of tampered envelope MUST fail
if ${HSMTOOL} --module "${MODULE}" ef import \
    --wrapping-key test-wrapping-key \
    "${TAMPERED_ENVELOPE}" 2>/dev/null; then
    echo "Error: Tampered envelope import should have failed authentication!" >&2
    exit 1
fi
echo "Tamper rejection verified: corrupted envelope was detected and rejected!"

echo "ALL KWP ELEMENTARY FILE TESTS PASSED!"
