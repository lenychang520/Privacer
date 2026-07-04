#!/usr/bin/env bash
# Install Privacer opencode plugin globally (all projects).
# Usage: bash scripts/setup-opencode-plugin.sh
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PLUGIN_SRC="$REPO_DIR/scripts/privacer-plugin.js"
WASM_SRC="$REPO_DIR/vscode-extension/wasm"

OPENCODE_CONFIG="${XDG_CONFIG_HOME:-$HOME/.config}/opencode"
PLUGIN_DST="$OPENCODE_CONFIG/plugins"

echo "Installing Privacer plugin for opencode..."
echo "  Target: $PLUGIN_DST"

# 1. Create plugin directory
mkdir -p "$PLUGIN_DST/wasm"

# 2. Copy plugin source
cp "$PLUGIN_SRC" "$PLUGIN_DST/privacer.js"

# 3. Copy WASM files (package.json needed so _require(dir) resolves the entry)
cp "$WASM_SRC/package.json"          "$PLUGIN_DST/wasm/"
cp "$WASM_SRC/privacer_wasm.js"      "$PLUGIN_DST/wasm/"
cp "$WASM_SRC/privacer_wasm_bg.wasm" "$PLUGIN_DST/wasm/"
cp "$WASM_SRC/privacer_wasm.d.ts"    "$PLUGIN_DST/wasm/" 2>/dev/null || true

# 4. Ensure global package.json has type: module + @opencode-ai/plugin
PACKAGE_JSON="$OPENCODE_CONFIG/package.json"
if [ -f "$PACKAGE_JSON" ]; then
  node -e "
    const p = require('$PACKAGE_JSON');
    p.type = 'module';
    p.dependencies = p.dependencies || {};
    p.dependencies['@opencode-ai/plugin'] = p.dependencies['@opencode-ai/plugin'] || 'latest';
    require('fs').writeFileSync('$PACKAGE_JSON', JSON.stringify(p, null, 2) + '\n');
  "
else
  cat > "$PACKAGE_JSON" <<- EOF
{
  "type": "module",
  "dependencies": {
    "@opencode-ai/plugin": "latest"
  }
}
EOF
fi

# opencode auto-discovers plugins in ~/.config/opencode/plugins/ at startup —
# no config file modification needed.

echo ""
echo "  ✓ Plugin installed to $PLUGIN_DST/privacer.js"
echo "  ✓ WASM installed to $PLUGIN_DST/wasm/"
echo ""
echo "  Restart opencode for the plugin to take effect."
echo "  Check logs: tail -f .privacer/logs/opencode-*.log"
