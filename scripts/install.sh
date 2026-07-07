#!/usr/bin/env bash
# Install Privacer opencode plugin — one command, works everywhere.
#
# Quick install (no clone needed):
#   curl -fsSL https://raw.githubusercontent.com/lenychang520/Privacer/master/scripts/install.sh | bash
#
# From local repo:
#   bash scripts/install.sh
set -euo pipefail

REPO="lenychang520/Privacer"
BRANCH="master"
GITHUB_RAW="https://raw.githubusercontent.com/$REPO/$BRANCH"

# Respect OPENCODE_CONFIG_DIR (custom config dir), then XDG, then default
OPENCODE_CONFIG="${OPENCODE_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/opencode}"
PLUGIN_DIR="$OPENCODE_CONFIG/plugins"
WASM_DIR="$PLUGIN_DIR/wasm"
PACKAGE_JSON="$OPENCODE_CONFIG/package.json"

echo "==> Installing Privacer plugin for opencode..."
echo "    Config dir: $OPENCODE_CONFIG"

# ── 1. Detect source (local repo vs remote) ─────────────────
# When piped through curl|bash, $0 is "bash" — not a file path.
# Only use local mode if $0 is a real file with privacer-plugin.js next to it.
MODE="remote"
SCRIPT_DIR=""
if [ -f "$0" ] 2>/dev/null; then
  CANDIDATE_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd || echo "")"
  if [ -n "$CANDIDATE_DIR" ] && [ -f "$CANDIDATE_DIR/privacer-plugin.js" ]; then
    CANDIDATE_WASM="$(cd "$CANDIDATE_DIR/../vscode-extension/wasm" 2>/dev/null && pwd || echo "")"
    if [ -n "$CANDIDATE_WASM" ] && [ -f "$CANDIDATE_WASM/privacer_wasm_bg.wasm" ]; then
      MODE="local"
      SCRIPT_DIR="$CANDIDATE_DIR"
      LOCAL_WASM="$CANDIDATE_WASM"
    fi
  fi
fi
echo "    Source: $MODE"

# ── 2. Environment checks ──────────────────────────────────
if ! command -v node &>/dev/null; then
  echo "  ✖ Node.js is required but not found."
  echo "    Install: https://nodejs.org or use your package manager."
  exit 1
fi

HAVE_BUN=false; HAVE_NPM=false
command -v bun &>/dev/null && HAVE_BUN=true
command -v npm &>/dev/null && HAVE_NPM=true
if ! $HAVE_BUN && ! $HAVE_NPM; then
  echo "  ✖ Neither bun nor npm is found."
  echo "    Install bun: curl -fsSL https://bun.sh/install | bash"
  echo "    (or npm: https://nodejs.org)"
  exit 1
fi
PACKAGE_MANAGER="npm"; $HAVE_BUN && PACKAGE_MANAGER="bun"
echo "    Package manager: $PACKAGE_MANAGER"

# ── 3. Create directories ──────────────────────────────────
mkdir -p "$WASM_DIR"

# ── 4. Install plugin + WASM files ─────────────────────────
if [ "$MODE" = "local" ]; then
  echo "    Copying plugin..."
  cp "$SCRIPT_DIR/privacer-plugin.js" "$PLUGIN_DIR/privacer.js"
  cp "$LOCAL_WASM/package.json"      "$WASM_DIR/"
  cp "$LOCAL_WASM/privacer_wasm.js"  "$WASM_DIR/"
  cp "$LOCAL_WASM/privacer_wasm_bg.wasm" "$WASM_DIR/"
  cp "$LOCAL_WASM/privacer_wasm.d.ts"    "$WASM_DIR/" 2>/dev/null || true
else
  echo "    Downloading plugin + WASM (~1.6 MB)..."
  curl -fsSL "$GITHUB_RAW/scripts/privacer-plugin.js" -o "$PLUGIN_DIR/privacer.js"
  curl -fsSL "$GITHUB_RAW/vscode-extension/wasm/package.json" -o "$WASM_DIR/package.json"
  curl -fsSL "$GITHUB_RAW/vscode-extension/wasm/privacer_wasm.js" -o "$WASM_DIR/privacer_wasm.js"
  curl -fsSL "$GITHUB_RAW/vscode-extension/wasm/privacer_wasm_bg.wasm" -o "$WASM_DIR/privacer_wasm_bg.wasm"
  curl -fsSL "$GITHUB_RAW/vscode-extension/wasm/privacer_wasm.d.ts" -o "$WASM_DIR/privacer_wasm.d.ts" 2>/dev/null || true
fi

# ── 5. Verify files ────────────────────────────────────────
if [ ! -f "$WASM_DIR/privacer_wasm_bg.wasm" ]; then
  echo "  ✖ WASM binary not found — install failed."
  exit 1
fi
WASM_SIZE=$(stat -c%s "$WASM_DIR/privacer_wasm_bg.wasm" 2>/dev/null || stat -f%z "$WASM_DIR/privacer_wasm_bg.wasm" 2>/dev/null || echo "0")
if [ "$WASM_SIZE" -lt 1000000 ]; then
  echo "  ✖ WASM binary appears corrupted (size: $WASM_SIZE bytes)."
  exit 1
fi

echo "    Plugin: $PLUGIN_DIR/privacer.js"
echo "    WASM: $WASM_DIR/ ($WASM_SIZE bytes)"

# ── 6. Set up package.json + install dependencies ──────────
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

echo "    Installing dependencies (cd $OPENCODE_CONFIG && ${PACKAGE_MANAGER} install)..."
(cd "$OPENCODE_CONFIG" && $PACKAGE_MANAGER install --no-audit --no-fund 2>&1 | sed 's/^/      /') || {
  echo "  ⚠  Dependency install failed. Try manually:"
  echo "    cd $OPENCODE_CONFIG && $PACKAGE_MANAGER install"
}

# ── 7. Quick verification ──────────────────────────────────
echo "    Verifying WASM loads correctly..."
node -e "
const { createRequire } = require('module');
const path = require('path');
const req = createRequire(process.cwd() + '/test.js');
const dir = '$WASM_DIR';
try {
  const mod = req(dir);
  const result = mod.filter('My IP is 192.168.1.1 and email is test@example.com', true);
  const repl = result.replacements();
  const out = result.text();
  result.free();
  if (repl > 0 && out.includes('[IP]')) {
    process.exit(0);
  }
  process.exit(2);
} catch (e) {
  console.error('  ✖ WASM load error:', e.message);
  process.exit(1);
}
" && echo "    WASM: verified ✓ (filtering works)" || echo "    WASM: warning — plugin files installed but verification failed"

# ── Done ────────────────────────────────────────────────────
echo ""
echo "  ✓ Privacer installed to $PLUGIN_DIR"
echo ""
echo "  Restart opencode for the plugin to take effect."
echo "  Check logs: tail -f .privacer/logs/opencode-*.log"
echo "  Expected: [INFO] Plugin initializing → WASM loaded → Plugin ready"
