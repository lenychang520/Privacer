# Privacer

> Detect and redact sensitive data in LLM requests — before they leave your machine.

## What is Privacer?

Privacer is a privacy filtering engine that intercepts LLM/AI API requests and redacts sensitive information (API keys, passwords, tokens, IP addresses, emails, phone numbers, credit cards, SSH keys, etc.) before the data reaches external servers.

The core engine is written in Rust and compiled to WebAssembly (WASM), allowing it to run inside any platform that supports WASM — VS Code extensions, CLI tools, Python plugins, and more.

## Architecture

```
                    ┌──────────────────────────┐
    │    privacer-core          │
    │   Rust + WASM (51 tests)  │
                    └──────────┬───────────────┘
                               │
          ┌────────────────────┼────────────────────┐
          ▼                    ▼                    ▼
   ┌─────────────┐    ┌──────────────┐    ┌──────────────┐
   │ VS Code Ext │    │ CLI Plugins  │    │ Python Plugins│
   │ (Trae etc.) │    │ (Claude Code)│    │ (Hermes)     │
   └─────────────┘    └──────────────┘    └──────────────┘
```

### Core Engine (`core/`)

| File | Description |
|------|-------------|
| `patterns.rs` | 27 regex rules for structured sensitive data (IP, email, phone, API keys, JWT, SSH keys, credit cards, etc.) |
| `entropy.rs` | Shannon entropy detection for unstructured secrets (high-entropy strings) |
| `detector.rs` | Core pipeline: normalize → match → deduplicate → replace |
| `preprocess.rs` | NFKC normalization, URL decode, HTML unescape, zero-width char stripping |
| `whitelist.rs` | Safe-listed values (localhost, 0.0.0.0, example.com, etc.) |
| `lib.rs` | Public API: `filter_text()`, `scan_text()` |

### WASM Bindings (`wasm/`)

Exports two functions for consumption by JS/TS/Python:
- `filter(text, enable_entropy) → { text, replacements }`
- `scan(text, enable_entropy) → match_count`

### VS Code Extension (`vscode-extension/`)

Packages the WASM core into a `.vsix` file installable on VS Code and its forks.

## Platform Support

| Platform | Interception Method | Status | Why |
|----------|-------------------|--------|-----|
| **Claude Code** | `UserPromptSubmit` hook | ✅ Ready | Native hook API — every prompt is filtered before reaching the LLM |
| **Hermes Agent** | `ProviderProfile.prepare_messages()` | ✅ Ready | Official provider plugin interface |
| **opencode** | Plugin system | 🔜 Next | Has native plugin support |
| **VS Code (Copilot)** | Extension host monkey-patch | ⚠️ Partial | LM API goes through IPC, not all requests interceptable |
| **Trae CN** | Extension (limited) | ❌ Blocked | AI requests go through `@aha-kit/ipc` (ZeroMQ) → separate subprocess → Chromium native net stack. Extension layer cannot reach them. |
| **Cursor** | Extension (limited) | ❌ Likely blocked | Same architecture as Trae — VS Code fork with proprietary AI network stack |
| **Windsurf** | Extension (limited) | ❌ Likely blocked | Same as above |

### Why VS Code forks (Trae/Cursor/Windsurf) are blocked

These IDEs embed their AI chat in a multi-layer architecture that bypasses the Node.js extension host:

1. **Webpack closure capture** — The AI extension bundles `require("http")` at build time, so monkey-patching `http.request` after the bundle loads has no effect.
2. **`@aha-kit/ipc` (ZeroMQ)** — AI requests are sent via native IPC protocol to a separate subprocess, not through standard HTTP.
3. **Chromium native net stack** — The subprocess uses a Rust native module (`@aha-kit/net` → ttnet) that talks directly to the OS network stack, completely bypassing Node.js.

No VS Code extension API can intercept traffic at this layer. The only reliable method for these IDEs is an HTTP proxy (`http.proxy` setting), but that requires the user to configure a proxy address — which conflicts with the zero-config design goal.

## Detection Capabilities

The engine detects and redacts:

| Category | Examples | Placeholder |
|----------|---------|-------------|
| IP addresses | `192.168.1.1`, `0x7f000001`, IPv6 | `[IP]` |
| Emails | `user@company.com` | `[EMAIL]` |
| Phone numbers | `13800138000`, `+1-555-1234567` | `[PHONE]` |
| API keys | `sk-...`, `Bearer ...`, `AKIA...` | `[API_KEY]` |
| SSH keys | `-----BEGIN RSA PRIVATE KEY-----` | `[SSH_KEY]` |
| GitHub tokens | `ghp_...`, `github_pat_...` | `[GITHUB_TOKEN]` |
| JWT tokens | `eyJ...` | `[JWT]` |
| Credit cards | `4111 1111 1111 1111` (Luhn validated) | `[CARD]` |
| Database URLs | `mysql://user:pass@host/db` | `[DB_URL]` |
| Credentials | `password=secret123`, `token=abc456` | `[CREDENTIAL]` |
| US SSN | `123-45-6789` | `[SSN]` |
| China ID card | `110101199001011234` | `[ID_CARD]` |
| UUID | `550e8400-e29b-41d4-a716-446655440000` | `[UUID]` |
| SHA hashes | 64-char hex strings | `[HASH]` |
| High-entropy secrets | Random strings with entropy ≥ 5.0 bits/char | `[SECRET]` |

### Whitelisted values (never filtered)

- `0.0.0.0`, `255.255.255.255`
- RFC 1918 private IPv4 (`10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`)
- `localhost`, `example.com`, `example.org`, `test.com`
- Common port numbers (22, 80, 443, 8080, etc.)

## Build

```bash
# Build Rust core
cd core && cargo test    # 51/51 tests pass
cd core && cargo build --release

# Build WASM
cd wasm && wasm-pack build --target nodejs --out-dir ../vscode-extension/wasm --no-opt

# Package VS Code extension
cd vscode-extension && npx tsc && npx @vscode/vsce package --allow-missing-repository
# Output: privacer-0.1.0.vsix
```

## Tech Stack

- **Core**: Rust 2024 edition, `fancy-regex` (lookaround support), `serde`, `unicode-normalization`
- **WASM**: `wasm-bindgen`, `wasm-pack`
- **VS Code Extension**: TypeScript, Node.js WASM loader
- **Python (Hermes)**: `wasmtime-py` for WASM loading

## License

Apache-2.0

## Project Origin

Privacer evolved from [llm-privacy-guard](https://github.com/lenychang520/llm-privacy-guard), a Python HTTP proxy-based privacy filter. The project pivoted from HTTP proxy to a Rust+WASM core with platform-native plugin distribution.
