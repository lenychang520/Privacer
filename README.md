# Privacer

> Detect and redact sensitive data in LLM requests — before they leave your machine.

## What is Privacer?

Privacer is a privacy filtering engine that can intercepts LLM/AI API requests and redacts sensitive information (API keys, passwords, tokens, IP addresses, emails, phone numbers, credit cards, SSH keys, etc.) before the data reaches external servers.

The core engine is written in Rust and compiled to WebAssembly (WASM), and ships as an **opencode plugin** that filters every LLM-bound message automatically.

## Architecture

```
                    ┌──────────────────────────┐
                    │    privacer-core          │
                    │   Rust + WASM (51 tests)  │
                    └──────────┬───────────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │  opencode plugin     │
                    │  (WASM via Node.js)  │
                    └──────────────────────┘
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

Exports two functions for consumption by JS/TS:
- `filter(text, enable_entropy) → { text, replacements }`
- `scan(text, enable_entropy) → match_count`

### opencode Plugin (`scripts/privacer-plugin.js`)

Installed to `~/.config/opencode/plugins/privacer.js`. Hooks into every opencode LLM request and redacts sensitive data in-place.

## Quick Start

```bash
bash scripts/setup-opencode-plugin.sh
```

Here's the English translation:

The script will automatically:
1. Copy the plugin and WASM to `~/.config/opencode/plugins/`
2. Install the `@opencode-ai/plugin` dependency

When opencode starts, it will automatically load plugins from the `plugins/` directory, no manual configuration changes needed.

Restart opencode to verify that the filtering takes effect:
```bash
tail -f .privacer/logs/opencode-*.log
# Expected: Plugin initializing → WASM loaded → Plugin ready
```

## Platform Support

| Platform | Status |
|----------|--------|
| **opencode** | ✅ Ready — native plugin, automatic filtering |
| **Claude Code** | 🔜 Future |
| **VS Code / Copilot** | 🔜 Future |
| **Trae / Cursor / Windsurf** | ❌ Blocked — AI requests bypass Node.js extension host entirely |

VS Code forks (Trae, Cursor, Windsurf) embed their AI chat in a multi-layer architecture that bypasses the Node.js extension host — Webpack closure capture, ZeroMQ IPC, and Chromium native net stack make interception from an extension impossible.

## Detection Capabilities

| Category | Placeholder |
|----------|-------------|
| IP addresses (v4, v6, hex) | `[IP]` |
| Emails | `[EMAIL]` |
| Phone numbers (China, international) | `[PHONE]` |
| API keys (sk-, pk-, Bearer) | `[API_KEY]` |
| AWS access keys | `[AWS_KEY]` |
| SSH keys (public/private blocks) | `[SSH_KEY]` |
| GitHub tokens (ghp_, github_pat_) | `[GITHUB_TOKEN]` |
| JWT tokens | `[JWT]` |
| Credit cards (Luhn validated) | `[CARD]` |
| Database connection URLs | `[DB_URL]` |
| DB CLI commands | `[DB_CMD]` |
| Credentials (password=, token=, API_KEY=) | `[CREDENTIAL]` |
| US SSN | `[SSN]` |
| China ID card | `[ID_CARD]` |
| UUID (with/without hyphens) | `[UUID]` |
| SHA hashes (64-char hex) | `[HASH]` |
| High-entropy secrets (≥5.0 bits/char) | `[SECRET]` |

### Whitelisted (never filtered)

- `0.0.0.0`, `255.255.255.255`
- RFC 1918 private IPv4 (`10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`)
- `localhost`, `example.com`, `example.org`, `test.com`

## Build

```bash
# Build & test core
cd core && cargo test

# Build WASM (requires wasm-pack)
cd wasm && wasm-pack build --target nodejs --out-dir ../vscode-extension/wasm --no-opt
```

## Tech Stack

- **Core**: Rust 2024 edition, `fancy-regex`, `serde`, `unicode-normalization`
- **WASM**: `wasm-bindgen`, `wasm-pack`
- **Plugin**: JavaScript, Node.js WASM loader
- **Platform**: opencode plugin system

## License

Apache-2.0
