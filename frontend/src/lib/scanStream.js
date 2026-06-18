// Pure, UI-free client for the backend SSE scan stream.
//
// The endpoint (POST /api/scan/stream) streams "data: <json>\n\n" frames whose
// JSON carries a `type`: start | progress | done | error. EventSource only does
// GET, so we read the response body ourselves with a ReadableStream reader and a
// buffer that survives chunk boundaries.
//
// This module has no React in it on purpose, so the parser and dispatch can be
// unit-tested later with a mocked stream.
import { API_URL, SCAN_STREAM_URL } from './config.js'

/**
 * Parse one SSE frame (the text between blank lines) into an event object.
 * Returns null for keep-alives, comments, or unparseable payloads. SSE allows
 * multiple `data:` lines per frame; they join with newlines before JSON parsing.
 */
export function parseFrame(frame) {
  const dataLines = []
  for (const line of frame.split('\n')) {
    if (line.startsWith('data:')) {
      dataLines.push(line.slice(5).replace(/^ /, ''))
    }
  }
  if (dataLines.length === 0) return null
  try {
    return JSON.parse(dataLines.join('\n'))
  } catch {
    return null
  }
}

/**
 * Split a running buffer into complete frames (separated by a blank line) and
 * the trailing remainder that has not finished arriving yet.
 * Returns [completeFrames, remainder].
 */
export function splitFrames(buffer) {
  const parts = buffer.split('\n\n')
  const remainder = parts.pop() ?? ''
  return [parts, remainder]
}

function friendlyNetworkMessage() {
  return `could not reach the scanner at ${API_URL}. Make sure the backend is running, then try again.`
}

/**
 * Run a scan against the streaming endpoint, dispatching events to callbacks.
 *
 * @param {string} systemPrompt
 * @param {object} handlers
 * @param {(event: {total: number}) => void} [handlers.onStart]
 * @param {(event: {current: number, total: number, attack_id: string, owasp_category: string}) => void} [handlers.onProgress]
 * @param {(result: object) => void} [handlers.onDone]
 * @param {(message: string) => void} [handlers.onError]
 * @param {AbortSignal} [handlers.signal]
 */
export async function runScanStream(
  systemPrompt,
  { onStart, onProgress, onDone, onError, signal } = {},
) {
  const dispatch = (event) => {
    if (!event || typeof event.type !== 'string') return
    switch (event.type) {
      case 'start':
        onStart?.(event)
        break
      case 'progress':
        onProgress?.(event)
        break
      case 'done':
        onDone?.(event.result)
        break
      case 'error':
        onError?.(event.message || 'the scan ended with an error.')
        break
      default:
        break
    }
  }

  let response
  try {
    response = await fetch(SCAN_STREAM_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'text/event-stream',
      },
      body: JSON.stringify({ system_prompt: systemPrompt }),
      signal,
    })
  } catch (err) {
    if (err?.name === 'AbortError') return
    onError?.(friendlyNetworkMessage())
    return
  }

  if (!response.ok || !response.body) {
    onError?.(`the server returned status ${response.status}.`)
    return
  }

  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''

  try {
    for (;;) {
      const { value, done } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })
      const [frames, remainder] = splitFrames(buffer)
      buffer = remainder
      for (const frame of frames) dispatch(parseFrame(frame))
    }
    // Flush the decoder and parse any final frame that arrived without a
    // trailing blank line.
    buffer += decoder.decode()
    if (buffer.trim()) dispatch(parseFrame(buffer))
  } catch (err) {
    if (err?.name === 'AbortError') return
    onError?.(friendlyNetworkMessage())
  }
}
