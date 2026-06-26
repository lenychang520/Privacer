import * as vscode from 'vscode';
import * as path from 'path';
import * as http from 'http';
import * as fs from 'fs';

// ── Logger ──────────────────────────────────────────────

let logDir: string;
let logStream: fs.WriteStream | null = null;

function initLogger(ctx: vscode.ExtensionContext) {
    logDir = path.join(ctx.globalStorageUri.fsPath, 'logs');
    try { fs.mkdirSync(logDir, { recursive: true }); } catch { }
    rotateLog();
}

function rotateLog() {
    logStream?.end();
    const d = new Date();
    const date = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
    const p = path.join(logDir, `vscode-${date}.log`);
    logStream = fs.createWriteStream(p, { flags: 'a' });
}

function log(level: string, msg: string, extra?: any) {
    const ts = new Date().toISOString();
    const line = `[${ts}] [${level}] [privacer] ${msg}${extra ? ' ' + JSON.stringify(extra) : ''}`;
    console.log(line);
    try {
        if (!logStream) rotateLog();
        logStream?.write(line + '\n');
    } catch { }
}

// ── WASM core ──────────────────────────────────────────────

let privacerWasm: any = null;

function loadWasmSync(context: vscode.ExtensionContext): boolean {
    try {
        const wasmDir = path.join(context.extensionPath, 'wasm');
        privacerWasm = require(wasmDir);
        log('INFO', `WASM loaded from ${wasmDir}`);
        return true;
    } catch (e: any) {
        log('ERROR', `WASM load failed: ${e.message}`);
        return false;
    }
}

// ── Patch state ────────────────────────────────────────────

const clientReqProto = http.ClientRequest.prototype as any;
let originalHttpWrite: any = null;
let originalHttpEnd: any = null;
let originalFetch: typeof globalThis.fetch | null = null;

const LLM_PATH_PATTERNS = [
    '/chat/completions',
    '/v1/messages',
    '/v1/chat/completions',
    '/llm_raw_chat',
    '/completions',
    '/api/ide/v1/llm_raw_chat',
    '/api/ide/v2/llm_raw_chat',
];

function isLLMRequest(reqPath: string): boolean {
    if (!reqPath) return false;
    return LLM_PATH_PATTERNS.some(p => reqPath.includes(p));
}

// ── Body filtering ──────────────────────────────────────────

function filterText(text: string): { text: string; redacted: number } {
    if (!privacerWasm || typeof privacerWasm.filter !== 'function') {
        return { text, redacted: 0 };
    }
    try {
        const result = privacerWasm.filter(text, true);
        const redacted = result.replacements();
        return { text: redacted > 0 ? result.text() : text, redacted };
    } catch (e: any) {
        log('ERROR', `filter error: ${e.message}`);
        return { text, redacted: 0 };
    }
}

function filterJsonBody(body: string): { text: string; redacted: number } {
    if (!privacerWasm || typeof privacerWasm.filter !== 'function') {
        return { text: body, redacted: 0 };
    }

    try {
        const parsed = JSON.parse(body);
        let totalRedacted = 0;

        if (parsed.messages && Array.isArray(parsed.messages)) {
            parsed.messages = parsed.messages.map((msg: any) => {
                if (msg.role === 'user' && typeof msg.content === 'string') {
                    const r = filterText(msg.content);
                    if (r.redacted > 0) { totalRedacted += r.redacted; return { ...msg, content: r.text }; }
                }
                if (msg.role === 'user' && Array.isArray(msg.content)) {
                    msg.content = msg.content.map((part: any) => {
                        if (part.type === 'text' && typeof part.text === 'string') {
                            const r = filterText(part.text);
                            if (r.redacted > 0) { totalRedacted += r.redacted; return { ...part, text: r.text }; }
                        }
                        return part;
                    });
                }
                return msg;
            });
        }

        if (parsed.content && Array.isArray(parsed.content)) {
            parsed.content = parsed.content.map((part: any) => {
                if (part.type === 'text' && typeof part.text === 'string') {
                    const r = filterText(part.text);
                    if (r.redacted > 0) { totalRedacted += r.redacted; return { ...part, text: r.text }; }
                }
                return part;
            });
        }

        for (const field of ['prompt', 'query', 'input', 'text']) {
            if (parsed[field] && typeof parsed[field] === 'string') {
                const r = filterText(parsed[field]);
                if (r.redacted > 0) { totalRedacted += r.redacted; parsed[field] = r.text; }
            }
        }

        if (totalRedacted > 0) {
            return { text: JSON.stringify(parsed), redacted: totalRedacted };
        }
    } catch { }

    const r = filterText(body);
    return r;
}

// ── HTTP request monkey-patch ──────────────────────────────

const requestBuffers = new WeakMap<http.ClientRequest, Buffer[]>();

function setupInterception(): void {
    // http.ClientRequest
    originalHttpWrite = clientReqProto.write;
    originalHttpEnd = clientReqProto.end;

    clientReqProto.write = function (this: http.ClientRequest, chunk: any, ...args: any[]): boolean {
        const reqPath = (this as any).path || '';
        if (isLLMRequest(reqPath)) {
            let buf = requestBuffers.get(this);
            if (!buf) { buf = []; requestBuffers.set(this, buf); }
            if (chunk) buf.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
            return true;
        }
        return originalHttpWrite.apply(this, [chunk, ...args] as any);
    };

    clientReqProto.end = function (this: http.ClientRequest, chunk?: any, ...args: any[]): http.ClientRequest {
        const reqPath = (this as any).path || '';
        if (!isLLMRequest(reqPath)) {
            return originalHttpEnd.apply(this, [chunk, ...args] as any);
        }
        let buf = requestBuffers.get(this) || [];
        if (chunk) buf.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        const fullBody = Buffer.concat(buf).toString('utf-8');
        log('INFO', `http.Request intercepted: ${reqPath}`);
        const { text: filteredBody, redacted } = filterJsonBody(fullBody);
        if (redacted > 0) {
            log('INFO', `http.Request: redacted ${redacted} item(s)`);
            const newBuf = Buffer.from(filteredBody);
            try { this.setHeader('Content-Length', newBuf.length.toString()); } catch { }
            if (newBuf.length > 0) originalHttpWrite.call(this, newBuf);
        } else {
            const origBuf = Buffer.from(fullBody);
            if (origBuf.length > 0) originalHttpWrite.call(this, origBuf);
        }
        requestBuffers.delete(this);
        return originalHttpEnd.apply(this, [] as any);
    };
    log('INFO', 'http.ClientRequest patched');

    // globalThis.fetch
    originalFetch = globalThis.fetch;
    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
        if (!isLLMRequest(url)) {
            return originalFetch!(input, init);
        }
        log('INFO', `fetch intercepted: ${url}`);
        if (init && init.body && typeof init.body === 'string') {
            const { text: filteredBody, redacted } = filterJsonBody(init.body);
            if (redacted > 0) {
                log('INFO', `fetch: redacted ${redacted} item(s)`);
                return originalFetch!(input, { ...init, body: filteredBody });
            }
        }
        return originalFetch!(input, init);
    };
    log('INFO', 'globalThis.fetch patched');
}

function teardownInterception(): void {
    if (originalHttpWrite) {
        clientReqProto.write = originalHttpWrite;
        originalHttpWrite = null;
    }
    if (originalHttpEnd) {
        clientReqProto.end = originalHttpEnd;
        originalHttpEnd = null;
    }
    if (originalFetch) {
        globalThis.fetch = originalFetch;
        originalFetch = null;
    }
    log('INFO', 'patches removed');
}

// ── Extension lifecycle ────────────────────────────────────

let activated = false;

export function activate(context: vscode.ExtensionContext) {
    initLogger(context);
    log('INFO', 'Extension activating...');

    if (activated) {
        log('WARN', 'Already activated, skipping');
        return;
    }
    activated = true;

    if (!loadWasmSync(context)) {
        log('WARN', 'WASM not loaded — filtering disabled');
        return;
    }

    setupInterception();
    vscode.window.showInformationMessage('Privacer: active — LLM requests are being filtered');

    context.subscriptions.push(
        vscode.commands.registerCommand('privacer.status', () => {
            vscode.window.showInformationMessage(
                privacerWasm
                    ? 'Privacer: active — LLM requests are being filtered'
                    : 'Privacer: WASM not loaded — filtering is inactive'
            );
        })
    );
}

export function deactivate() {
    if (activated) {
        teardownInterception();
        logStream?.end();
        logStream = null;
        activated = false;
    }
}
