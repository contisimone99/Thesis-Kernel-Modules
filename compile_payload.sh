#!/bin/bash
set -euo pipefail



FX_C="$HOME/qemu/hw/misc/fx.c"
PAYLOAD_S="payload.S"
OBJ="payload.o"
BIN="payload.bin"
TMPDIR=".payload_build_tmp"
TMP_FULL="$TMPDIR/payload_xxd.full"
TMP_BYTES="$TMPDIR/payload_xxd.bytes"
TMP_REPL="$TMPDIR/payload_repl.txt"

mkdir -p "$TMPDIR"

if [[ ! -f "$PAYLOAD_S" ]]; then
  echo "Error: $PAYLOAD_S not found" >&2
  exit 1
fi
if [[ ! -f "$FX_C" ]]; then
  echo "Error: fx.c not found at: $FX_C" >&2
  exit 1
fi

# 1) Assemble + extract .text as raw binary
as --64 -o "$OBJ" "$PAYLOAD_S"
objcopy -O binary -j .text "$OBJ" "$BIN"

# 2) Generate C bytes via xxd
xxd -i "$BIN" > "$TMP_FULL"

# Extract only the lines inside { ... } (portable for mawk/gawk)
awk '
  BEGIN { inside=0 }
  /{[[:space:]]*$/ { inside=1; next }
  inside==1 && /}[[:space:]]*;[[:space:]]*$/ { inside=0; next }
  inside==1 { print }
' "$TMP_FULL" > "$TMP_BYTES"

if [[ ! -s "$TMP_BYTES" ]]; then
  echo "Error: failed to extract bytes from xxd output" >&2
  exit 1
fi

# Build replacement snippet between markers in fx.c
cat > "$TMP_REPL" <<'EOF'
/* FX_PAYLOAD_BLOB_BEGIN */
static const uint8_t payload[] = {
EOF
sed 's/^/    /' "$TMP_BYTES" >> "$TMP_REPL"
cat >> "$TMP_REPL" <<'EOF'
};
/* FX_PAYLOAD_BLOB_END */
EOF

# 3) Sanity: ensure markers exist in fx.c
if ! grep -q "FX_PAYLOAD_BLOB_BEGIN" "$FX_C" || ! grep -q "FX_PAYLOAD_BLOB_END" "$FX_C"; then
  echo "Error: markers not found in $FX_C" >&2
  echo "Add these markers around payload[] in fx_step1_write_payload():" >&2
  echo "  /* FX_PAYLOAD_BLOB_BEGIN */" >&2
  echo "  static const uint8_t payload[] = { 0 };" >&2
  echo "  /* FX_PAYLOAD_BLOB_END */" >&2
  exit 1
fi

# 4) Patch fx.c: replace everything between markers (inclusive)
awk -v repl_file="$TMP_REPL" '
  BEGIN {
    repl = "";
    while ((getline line < repl_file) > 0) repl = repl line "\n";
    close(repl_file);
    inside=0;
    replaced=0;
  }
  /\/\* FX_PAYLOAD_BLOB_BEGIN \*\// {
    printf "%s", repl;
    inside=1;
    replaced=1;
    next;
  }
  /\/\* FX_PAYLOAD_BLOB_END \*\// {
    inside=0;
    next;
  }
  inside==1 { next; }
  { print }
  END {
    if (replaced==0) exit 42;
  }
' "$FX_C" > "$FX_C.patched"

mv "$FX_C.patched" "$FX_C"

LEN=$(wc -c < "$BIN" | tr -d ' ')
echo "OK: patched payload into $FX_C (payload.bin size=${LEN} bytes)"

# Cleanup
rm -rf "$TMPDIR"
rm -f "$OBJ" "$BIN"