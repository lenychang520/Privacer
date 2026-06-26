#!/usr/bin/env bash
# Setup Privacer opencode plugin — copy WASM to plugin directory
set -euo pipefail

PLUGIN_DIR="$(dirname "$0")/../.opencode/plugins"
WASM_SRC="$(dirname "$0")/../vscode-extension/wasm"
WASM_DST="$PLUGIN_DIR/wasm"

mkdir -p "$WASM_DST"
cp "$WASM_SRC/privacer_wasm.js" "$WASM_DST/"
cp "$WASM_SRC/privacer_wasm_bg.wasm" "$WASM_DST/"
cp "$WASM_SRC/privacer_wasm.d.ts" "$WASM_DST/" 2>/dev/null || true

echo "✓ WASM copied to $WASM_DST"
echo "✓ Privacer opencode plugin ready"
