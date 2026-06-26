import * as fs from 'fs'
import * as path from 'path'
import { Logger } from './logger'

export interface PrivacerWasm {
  filter(text: string, enableEntropy: boolean): { text(): string; replacements(): number }
  scan(text: string, enableEntropy: boolean): number
}

export type WasmSource = string | PrivacerWasm

export function resolveWasm(source: WasmSource, logger: Logger): PrivacerWasm | null {
  if (typeof source !== 'string') {
    logger.debug('Using pre-loaded WASM module')
    return source
  }

  const dir = source
  const jsPath = path.join(dir, 'privacer_wasm.js')
  const wasmPath = path.join(dir, 'privacer_wasm_bg.wasm')

  if (!fs.existsSync(jsPath)) {
    logger.error('WASM JS glue not found at', jsPath)
    return null
  }
  if (!fs.existsSync(wasmPath)) {
    logger.error('WASM binary not found at', wasmPath)
    return null
  }

  try {
    const mod = require(dir)
    logger.info('WASM loaded from', dir)
    return mod as PrivacerWasm
  } catch (e) {
    logger.error('Failed to load WASM:', e)
    return null
  }
}
