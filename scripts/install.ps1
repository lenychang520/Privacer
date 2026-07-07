# Install Privacer opencode plugin — Windows native (PowerShell)
#
# Quick install (no clone needed):
#   iex (irm https://raw.githubusercontent.com/lenychang520/Privacer/master/scripts/install.ps1)
#
# From local repo:
#   ./scripts/install.ps1
$ErrorActionPreference = "Stop"

$Repo = "lenychang520/Privacer"
$Branch = "master"
$GithubRaw = "https://raw.githubusercontent.com/$Repo/$Branch"

# Config directory — respect OPENCODE_CONFIG_DIR, then default to %USERPROFILE%\.config\opencode
if ($env:OPENCODE_CONFIG_DIR) {
    $ConfigDir = $env:OPENCODE_CONFIG_DIR
} else {
    $ConfigDir = Join-Path $env:USERPROFILE ".config\opencode"
}
$PluginDir = Join-Path $ConfigDir "plugins"
$WasmDir = Join-Path $PluginDir "wasm"
$PackageJson = Join-Path $ConfigDir "package.json"

Write-Host "==> Installing Privacer plugin for opencode..."
Write-Host "    Config dir: $ConfigDir"

# ── 1. Detect source (local repo vs remote) ─────────────────
# When piped via iex(irm url), $MyInvocation.MyCommand.Path is empty.
$Mode = "remote"
$ScriptDir = ""
if ($MyInvocation.MyCommand.Path) {
    $ScriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
    if (Test-Path (Join-Path $ScriptDir "privacer-plugin.js")) {
        $CandidateWasm = Join-Path $ScriptDir "..\vscode-extension\wasm"
        if (Test-Path (Join-Path $CandidateWasm "privacer_wasm_bg.wasm")) {
            $Mode = "local"
            $LocalWasm = (Resolve-Path $CandidateWasm).Path
        }
    }
}
Write-Host "    Source: $Mode"

# ── 2. Environment checks ──────────────────────────────────
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Host "  [X] Node.js is required but not found."
    Write-Host "      Install: https://nodejs.org"
    exit 1
}

$HaveBun = [bool](Get-Command bun -ErrorAction SilentlyContinue)
$HaveNpm = [bool](Get-Command npm -ErrorAction SilentlyContinue)
if (-not $HaveBun -and -not $HaveNpm) {
    Write-Host "  [X] Neither bun nor npm is found."
    Write-Host "      Install bun: irm bun.sh/install.ps1 | iex"
    Write-Host "      (or npm: https://nodejs.org)"
    exit 1
}
$PkgManager = if ($HaveBun) { "bun" } else { "npm" }
Write-Host "    Package manager: $PkgManager"

# ── 3. Create directories ──────────────────────────────────
New-Item -ItemType Directory -Force -Path $WasmDir | Out-Null

# ── 4. Install plugin + WASM files ─────────────────────────
if ($Mode -eq "local") {
    Write-Host "    Copying plugin..."
    Copy-Item (Join-Path $ScriptDir "privacer-plugin.js") (Join-Path $PluginDir "privacer.js") -Force
    Copy-Item (Join-Path $LocalWasm "package.json") $WasmDir -Force
    Copy-Item (Join-Path $LocalWasm "privacer_wasm.js") $WasmDir -Force
    Copy-Item (Join-Path $LocalWasm "privacer_wasm_bg.wasm") $WasmDir -Force
    $dts = Join-Path $LocalWasm "privacer_wasm.d.ts"
    if (Test-Path $dts) { Copy-Item $dts $WasmDir -Force }
} else {
    Write-Host "    Downloading plugin + WASM (~1.6 MB)..."
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest "$GithubRaw/scripts/privacer-plugin.js" -OutFile (Join-Path $PluginDir "privacer.js") -UseBasicParsing
    Invoke-WebRequest "$GithubRaw/vscode-extension/wasm/package.json" -OutFile (Join-Path $WasmDir "package.json") -UseBasicParsing
    Invoke-WebRequest "$GithubRaw/vscode-extension/wasm/privacer_wasm.js" -OutFile (Join-Path $WasmDir "privacer_wasm.js") -UseBasicParsing
    Invoke-WebRequest "$GithubRaw/vscode-extension/wasm/privacer_wasm_bg.wasm" -OutFile (Join-Path $WasmDir "privacer_wasm_bg.wasm") -UseBasicParsing
    try {
        Invoke-WebRequest "$GithubRaw/vscode-extension/wasm/privacer_wasm.d.ts" -OutFile (Join-Path $WasmDir "privacer_wasm.d.ts") -UseBasicParsing
    } catch {}
}

# ── 5. Verify files ────────────────────────────────────────
$wasmFile = Join-Path $WasmDir "privacer_wasm_bg.wasm"
if (-not (Test-Path $wasmFile)) {
    Write-Host "  [X] WASM binary not found — install failed."
    exit 1
}
$wasmSize = (Get-Item $wasmFile).Length
if ($wasmSize -lt 1000000) {
    Write-Host "  [X] WASM binary appears corrupted (size: $wasmSize bytes)."
    exit 1
}

Write-Host "    Plugin: $(Join-Path $PluginDir 'privacer.js')"
Write-Host "    WASM: $WasmDir ($wasmSize bytes)"

# ── 6. Set up package.json + install dependencies ──────────
if (Test-Path $PackageJson) {
    $p = Get-Content $PackageJson -Raw | ConvertFrom-Json
    if (-not $p.PSObject.Properties['type']) {
        $p | Add-Member -NotePropertyName 'type' -NotePropertyValue 'module'
    } else {
        $p.type = 'module'
    }
    if (-not $p.PSObject.Properties['dependencies']) {
        $p | Add-Member -NotePropertyName 'dependencies' -NotePropertyValue ([ordered]@{})
    }
    if (-not $p.dependencies.PSObject.Properties['@opencode-ai/plugin']) {
        $p.dependencies | Add-Member -NotePropertyName '@opencode-ai/plugin' -NotePropertyValue 'latest'
    }
    $p | ConvertTo-Json -Depth 10 | Set-Content $PackageJson -Encoding UTF8
} else {
    @{ type = 'module'; dependencies = @{ '@opencode-ai/plugin' = 'latest' } } | ConvertTo-Json | Set-Content $PackageJson -Encoding UTF8
}

Write-Host "    Installing dependencies (cd $ConfigDir; $PkgManager install)..."
Push-Location $ConfigDir
try {
    & $PkgManager install --no-audit --no-fund 2>&1 | ForEach-Object { Write-Host "      $_" }
} catch {
    Write-Host "  [!] Dependency install failed. Try manually:"
    Write-Host "      cd $ConfigDir; $PkgManager install"
}
Pop-Location

# ── 7. Quick verification ──────────────────────────────────
Write-Host "    Verifying WASM loads correctly..."
# Use forward slashes in path — Node.js handles them on Windows
$wasmPathFwd = $WasmDir -replace '\\', '/'
$verifyCode = @"
const { createRequire } = require('module');
const req = createRequire(process.cwd() + '/test.js');
const dir = '$wasmPathFwd';
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
  console.error('  WASM load error:', e.message);
  process.exit(1);
}
"@

$verifyResult = node -e $verifyCode 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "    WASM: verified (filtering works)"
} else {
    Write-Host "    WASM: warning - plugin files installed but verification failed"
    Write-Host "      $verifyResult"
}

# ── Done ────────────────────────────────────────────────────
Write-Host ""
Write-Host "  [v] Privacer installed to $PluginDir"
Write-Host ""
Write-Host "  Restart opencode for the plugin to take effect."
Write-Host "  Check logs: Get-Content .privacer\logs\opencode-*.log -Wait"
Write-Host "  Expected: [INFO] Plugin initializing -> WASM loaded -> Plugin ready"
