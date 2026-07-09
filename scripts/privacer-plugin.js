import path from 'path'
import fs from 'fs'
import { fileURLToPath } from 'url'
import { createRequire } from 'module'

const _require = createRequire(import.meta.url)
const __dirname = path.dirname(fileURLToPath(import.meta.url))

let projectDir = null
function logDir() {
  return path.join(projectDir || process.cwd(), '.privacer', 'logs')
}

function ensureDir(dir) {
  try { fs.mkdirSync(dir, { recursive: true }) } catch { }
}

function logFile() {
  const d = new Date()
  const date = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
  return path.join(logDir(), `opencode-${date}.log`)
}

let logStream = null
function writeLog(level, msg, extra) {
  const ts = new Date().toISOString()
  const line = `[${ts}] [${level}] [opencode-plugin] ${msg}${extra ? ' ' + JSON.stringify(extra) : ''}`
  process.stdout.write(line + '\n')
  try {
    if (!logStream) {
      ensureDir(logDir())
      logStream = fs.createWriteStream(logFile(), { flags: 'a' })
    }
    logStream.write(line + '\n')
  } catch { }
}

function loadWasm() {
  const candidates = []
  if (process.env.PRIVACER_WASM_DIR) {
    candidates.push(process.env.PRIVACER_WASM_DIR)
  }
  candidates.push(path.join(__dirname, 'wasm'))

  for (const dir of candidates) {
    const jsPath = path.join(dir, 'privacer_wasm.js')
    if (fs.existsSync(jsPath)) {
      try {
        const mod = _require(dir)
        writeLog('INFO', `WASM loaded from ${dir}`)
        return mod
      } catch (e) {
        writeLog('WARN', `WASM found but failed to load from ${dir}: ${e.message}`)
      }
    }
  }
  writeLog('ERROR', 'WASM not found in any search path')
  return null
}

function filterText(text) {
  if (!wasm || typeof text !== 'string' || !text.trim()) return { text, redacted: 0 }
  try {
    const result = wasm.filter(text, entropyEnabled)
    const redacted = result.replacements()
    const out = redacted > 0 ? result.text() : text
    try { result.free() } catch { }
    return { text: out, redacted }
  } catch (e) {
    writeLog('ERROR', `Filter failed: ${e.message}`)
    return { text, redacted: 0 }
  }
}

function filterParts(parts) {
  if (!parts || !parts.length) return 0
  let total = 0
  for (const part of parts) {
    if (part.type === 'text' && typeof part.text === 'string') {
      const r = filterText(part.text)
      if (r.redacted > 0) {
        part.text = r.text
        total += r.redacted
      }
    }
    if (part.type === 'reasoning' && typeof part.text === 'string') {
      const r = filterText(part.text)
      if (r.redacted > 0) {
        part.text = r.text
        total += r.redacted
      }
    }
    if (part.type === 'tool' && part.state) {
      if (typeof part.state.output === 'string') {
        const r = filterText(part.state.output)
        if (r.redacted > 0) {
          part.state.output = r.text
          total += r.redacted
        }
      }
      if (typeof part.state.error === 'string') {
        const r = filterText(part.state.error)
        if (r.redacted > 0) {
          part.state.error = r.text
          total += r.redacted
        }
      }
    }
    if (part.type === 'file' && part.source && part.source.text && typeof part.source.text.value === 'string') {
      const r = filterText(part.source.text.value)
      if (r.redacted > 0) {
        part.source.text.value = r.text
        total += r.redacted
      }
    }
  }
  return total
}

let wasm = null
let entropyEnabled = process.env.PRIVACER_ENTROPY !== 'false'

export const PrivacerPlugin = async ({ project, directory }) => {
  projectDir = directory || project?.path || process.cwd()
  writeLog('INFO', `Plugin initializing, project: ${project?.name || 'unknown'}`)
  wasm = loadWasm()

  if (!wasm) {
    writeLog('WARN', 'Plugin loaded but WASM unavailable — filtering disabled')
  } else {
    writeLog('INFO', 'Plugin ready — filtering active')
  }

  return {
    "tool.execute.after": async (input, output) => {
      if (!wasm) return
      if (typeof output.output === 'string') {
        const r = filterText(output.output)
        if (r.redacted > 0) {
          output.output = r.text
          writeLog('INFO', `Redacted ${r.redacted} item(s) from ${input.tool} tool output`, {
            tool: input.tool,
            redacted: r.redacted,
          })
        }
      }
    },

    "experimental.chat.messages.transform": async (_input, output) => {
      if (!wasm) return

      const messages = output.messages
      if (!messages || !messages.length) return

      let totalRedacted = 0

      for (const msg of messages) {
        totalRedacted += filterParts(msg.parts)

        if (msg.info) {
          if (typeof msg.info.system === 'string') {
            const r = filterText(msg.info.system)
            if (r.redacted > 0) {
              msg.info.system = r.text
              totalRedacted += r.redacted
            }
          }
          if (msg.info.summary && typeof msg.info.summary.body === 'string') {
            const r = filterText(msg.info.summary.body)
            if (r.redacted > 0) {
              msg.info.summary.body = r.text
              totalRedacted += r.redacted
            }
          }
        }
      }

      if (totalRedacted > 0) {
        writeLog('INFO', `Redacted ${totalRedacted} sensitive item(s) from messages`)
      }
    },
  }
}
