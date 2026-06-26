import * as fs from 'fs'
import * as path from 'path'
import { Logger, LogLevel } from './logger'
import { resolveWasm, PrivacerWasm, WasmSource } from './wasm-loader'

export { Logger, LogLevel }
export type { PrivacerWasm, WasmSource }

export interface PrivacerOptions {
  wasmDir?: string
  wasmModule?: PrivacerWasm
  logDir?: string
  logLevel?: LogLevel
  enableEntropy?: boolean
}

export interface FilterResult {
  text: string
  redacted: number
}

const DEFAULT_LOG_DIR = '.privacer/logs'

export class Privacer {
  private wasm: PrivacerWasm | null = null
  private logger: Logger
  private enableEntropy: boolean
  private logDir: string

  constructor(options: PrivacerOptions = {}) {
    this.logDir = options.logDir || DEFAULT_LOG_DIR
    this.logger = new Logger(this.logDir, options.logLevel || 'info')
    this.enableEntropy = options.enableEntropy ?? true

    if (options.wasmModule) {
      this.wasm = options.wasmModule
      this.logger.info('Privacer initialized with provided WASM module')
    } else if (options.wasmDir) {
      this.wasm = resolveWasm(options.wasmDir, this.logger)
    } else {
      this.logger.warn('No WASM source provided — call load() later or provide wasmDir/wasmModule')
    }
  }

  load(wasmDir: string): boolean {
    this.wasm = resolveWasm(wasmDir, this.logger)
    return this.wasm !== null
  }

  loadModule(mod: PrivacerWasm): void {
    this.wasm = mod
    this.logger.info('WASM module loaded via loadModule()')
  }

  isReady(): boolean {
    return this.wasm !== null
  }

  filterText(text: string): FilterResult {
    if (!this.wasm) {
      this.logger.error('filterText called but WASM not loaded')
      return { text, redacted: 0 }
    }
    try {
      const result = this.wasm.filter(text, this.enableEntropy)
      const redacted = result.replacements()
      if (redacted > 0) {
        this.logger.info(`filterText: redacted ${redacted} item(s)`)
      }
      return { text: result.text(), redacted }
    } catch (e) {
      this.logger.error('filterText error:', e)
      return { text, redacted: 0 }
    }
  }

  scanText(text: string): number {
    if (!this.wasm) {
      this.logger.error('scanText called but WASM not loaded')
      return 0
    }
    try {
      const count = this.wasm.scan(text, this.enableEntropy)
      if (count > 0) {
        this.logger.info(`scanText: found ${count} sensitive item(s)`)
      }
      return count
    } catch (e) {
      this.logger.error('scanText error:', e)
      return 0
    }
  }

  setLogLevel(level: LogLevel) {
    this.logger.setLevel(level)
  }

  setEntropy(enabled: boolean) {
    this.enableEntropy = enabled
    this.logger.info(`Entropy detection ${enabled ? 'enabled' : 'disabled'}`)
  }

  dispose() {
    this.logger.dispose()
  }
}

export function createPrivacer(options: PrivacerOptions = {}): Privacer {
  return new Privacer(options)
}
