import * as vscode from 'vscode';
import * as path from 'path';
import * as http from 'http';
import * as fs from 'fs';

// ── Logger (to file only, survive crash) ────────────────

let logDir: string;
let logStream: fs.WriteStream | null = null;

function initLog(ctx: vscode.ExtensionContext) {
    logDir = path.join(ctx.globalStorageUri.fsPath, 'logs');
    try { fs.mkdirSync(logDir, { recursive: true }); } catch { }
    const d = new Date();
    const date = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
    logStream = fs.createWriteStream(path.join(logDir, `vscode-${date}.log`), { flags: 'a' });
}

function wlog(msg: string) {
    const ts = new Date().toISOString();
    const line = `[${ts}] [diag] ${msg}`;
    try { logStream?.write(line + '\n'); } catch { }
    try { console.log(line); } catch { }
}

// ── Heartbeat ────────────────────────────────────────────

let heartbeatTimer: any = null;

function startHeartbeat() {
    let count = 0;
    heartbeatTimer = setInterval(() => {
        count++;
        wlog(`HEARTBEAT #${count} — extension alive`);
    }, 10000);
}

// ── Patch ALL fetch / http, log everything ───────────────

let interceptedFetch = 0;
let interceptedHttp = 0;

function setupDiag() {
    // http.ClientRequest — log ALL
    const proto = http.ClientRequest.prototype as any;
    const origWrite = proto.write;
    const origEnd = proto.end;

    proto.write = function (this: any, chunk: any, ...args: any[]) {
        const p = this.path || '(no path)';
        interceptedHttp++;
        wlog(`HTTP write #${interceptedHttp}: ${p} bytes=${chunk?.length || 0}`);
        return origWrite.apply(this, [chunk, ...args]);
    };

    proto.end = function (this: any, chunk?: any, ...args: any[]) {
        const p = this.path || '(no path)';
        wlog(`HTTP end: ${p}`);
        return origEnd.apply(this, [chunk, ...args]);
    };
    wlog('http.ClientRequest patched');

    // globalThis.fetch — log ALL
    const origFetch = globalThis.fetch;
    if (typeof origFetch === 'function') {
        const fet = origFetch;
        globalThis.fetch = async (input: any, init?: any) => {
            interceptedFetch++;
            const url = typeof input === 'string' ? input : input?.url || '(unknown)';
            wlog(`FETCH #${interceptedFetch}: ${url}`);
            try {
                const res = await fet(input, init);
                wlog(`FETCH #${interceptedFetch} DONE: ${url} status=${res.status}`);
                return res;
            } catch (e: any) {
                wlog(`FETCH #${interceptedFetch} ERROR: ${url} ${e.message}`);
                throw e;
            }
        };
        wlog('globalThis.fetch patched');
    } else {
        wlog('globalThis.fetch is NOT available (typeof=' + typeof origFetch + ')');
    }
}

function teardownDiag() {
    wlog('DIAG TEARDOWN — extension deactivating');
    if (heartbeatTimer) clearInterval(heartbeatTimer);
    wlog(`Stats: fetch calls=${interceptedFetch} http calls=${interceptedHttp}`);
    try { logStream?.end(); } catch { }
    logStream = null;
}

// ── Lifecycle ─────────────────────────────────────────────

let active = false;

export function activate(context: vscode.ExtensionContext) {
    initLog(context);
    wlog('=== ACTIVATE ===');
    wlog(`extensionPath=${context.extensionPath}`);
    wlog(`globalStoragePath=${context.globalStorageUri.fsPath}`);

    if (active) { wlog('SKIP — already active'); return; }
    active = true;

    try {
        setupDiag();
        startHeartbeat();
        wlog('=== ACTIVATION COMPLETE ===');
    } catch (e: any) {
        wlog('ACTIVATION ERROR: ' + e.message + '\n' + (e.stack || ''));
    }
}

export function deactivate() {
    wlog('=== DEACTIVATE ===');
    teardownDiag();
    active = false;
}
