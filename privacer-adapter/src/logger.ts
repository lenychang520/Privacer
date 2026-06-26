import * as fs from 'fs'
import * as path from 'path'

export type LogLevel = 'debug' | 'info' | 'warn' | 'error'

const LEVEL_NUM: Record<LogLevel, number> = {
  debug: 0, info: 1, warn: 2, error: 3,
}

const LEVEL_LABEL: Record<LogLevel, string> = {
  debug: 'DBG', info: 'INF', warn: 'WRN', error: 'ERR',
}

export class Logger {
  private minLevel: number
  private logDir: string
  private today: string = ''
  private stream: fs.WriteStream | null = null

  constructor(logDir: string, level: LogLevel = 'info') {
    this.minLevel = LEVEL_NUM[level]
    this.logDir = logDir
    this.ensureLogDir()
  }

  setLevel(level: LogLevel) {
    this.minLevel = LEVEL_NUM[level]
    this.info(`Log level set to ${level}`)
  }

  debug(msg: string, ...args: any[]) { this.write('debug', msg, args) }
  info(msg: string, ...args: any[]) { this.write('info', msg, args) }
  warn(msg: string, ...args: any[]) { this.write('warn', msg, args) }
  error(msg: string, ...args: any[]) { this.write('error', msg, args) }

  private ensureLogDir() {
    try {
      fs.mkdirSync(this.logDir, { recursive: true })
    } catch { /* ignore */ }
  }

  private getDateKey(): string {
    const d = new Date()
    return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`
  }

  private rotateFile() {
    const today = this.getDateKey()
    if (today === this.today && this.stream) return
    this.stream?.end()
    this.stream = null
    this.today = today
    const logPath = path.join(this.logDir, `privacer-${today}.log`)
    this.stream = fs.createWriteStream(logPath, { flags: 'a' })
  }

  private write(level: LogLevel, msg: string, args: any[]) {
    if (LEVEL_NUM[level] < this.minLevel) return

    const ts = new Date().toISOString()
    const label = LEVEL_LABEL[level]
    const extra = args.length ? ' ' + args.map(a => {
      if (typeof a === 'object') { try { return JSON.stringify(a) } catch { return String(a) } }
      return String(a)
    }).join(' ') : ''
    const line = `[${ts}] [${label}] ${msg}${extra}`

    // stdout
    if (level === 'error') {
      process.stderr.write(line + '\n')
    } else {
      process.stdout.write(line + '\n')
    }

    // file
    this.rotateFile()
    if (this.stream) {
      this.stream.write(line + '\n')
    }
  }

  dispose() {
    this.stream?.end()
    this.stream = null
  }
}
