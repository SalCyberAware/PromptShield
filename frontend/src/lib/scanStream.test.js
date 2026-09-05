import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { parseFrame, runScanStream, splitFrames } from './scanStream.js'
import { API_URL, SCAN_STREAM_URL } from './config.js'

// A frame as the backend writes it: one `data:` line, then the blank line.
const frame = (payload) => `data: ${JSON.stringify(payload)}\n\n`

const DONE_RESULT = { attacks_total: 13, results: [], summary: {} }

/**
 * Build the minimum of a fetch Response that runScanStream actually touches:
 * `ok`, `status`, and a `body` exposing getReader(). Each string in `chunks` is
 * handed back as one read(), so tests control exactly where chunk boundaries fall.
 */
function streamResponse(chunks, { ok = true, status = 200, body = true } = {}) {
  const encoder = new TextEncoder()
  return byteResponse(
    chunks.map((chunk) => encoder.encode(chunk)),
    { ok, status, body },
  )
}

/** The same, but the caller supplies raw byte chunks (to cut mid-character). */
function byteResponse(chunks, { ok = true, status = 200, body = true } = {}) {
  let index = 0
  return {
    ok,
    status,
    body: body
      ? {
          getReader: () => ({
            read: async () =>
              index < chunks.length
                ? { value: chunks[index++], done: false }
                : { value: undefined, done: true },
          }),
        }
      : null,
  }
}

/** A response whose reader rejects part-way through, like a torn connection. */
function failingResponse(chunks, error) {
  const encoder = new TextEncoder()
  let index = 0
  return {
    ok: true,
    status: 200,
    body: {
      getReader: () => ({
        read: async () => {
          if (index < chunks.length) {
            return { value: encoder.encode(chunks[index++]), done: false }
          }
          throw error
        },
      }),
    },
  }
}

function abortError() {
  const err = new Error('The operation was aborted.')
  err.name = 'AbortError'
  return err
}

function handlers() {
  return {
    onStart: vi.fn(),
    onProgress: vi.fn(),
    onDone: vi.fn(),
    onError: vi.fn(),
  }
}

describe('parseFrame', () => {
  it('parses a start frame', () => {
    expect(parseFrame('data: {"type":"start","total":13}')).toEqual({
      type: 'start',
      total: 13,
    })
  })

  it('parses a progress frame', () => {
    const event = parseFrame(
      'data: {"type":"progress","current":3,"total":13,"attack_id":"pi_001","owasp_category":"LLM01"}',
    )
    expect(event).toEqual({
      type: 'progress',
      current: 3,
      total: 13,
      attack_id: 'pi_001',
      owasp_category: 'LLM01',
    })
  })

  it('parses a done frame and keeps the nested result intact', () => {
    const event = parseFrame(
      `data: ${JSON.stringify({ type: 'done', result: DONE_RESULT })}`,
    )
    expect(event.type).toBe('done')
    expect(event.result).toEqual(DONE_RESULT)
  })

  it('parses an error frame', () => {
    expect(parseFrame('data: {"type":"error","message":"upstream refused"}')).toEqual({
      type: 'error',
      message: 'upstream refused',
    })
  })

  it('accepts a data line with no space after the colon', () => {
    expect(parseFrame('data:{"type":"start","total":1}')).toEqual({
      type: 'start',
      total: 1,
    })
  })

  it('joins multiple data lines in one frame before parsing', () => {
    expect(parseFrame('data: {"type":"start",\ndata: "total":13}')).toEqual({
      type: 'start',
      total: 13,
    })
  })

  it('ignores non-data lines such as comments, ids and event names', () => {
    const raw = [
      ': keep-alive',
      'event: message',
      'id: 7',
      'data: {"type":"start","total":2}',
    ].join('\n')
    expect(parseFrame(raw)).toEqual({ type: 'start', total: 2 })
  })

  it('returns null instead of throwing on malformed JSON', () => {
    expect(parseFrame('data: {"type":"start"')).toBeNull()
    expect(parseFrame('data: not json at all')).toBeNull()
  })

  it('returns null for empty frames and keep-alive comments', () => {
    expect(parseFrame('')).toBeNull()
    expect(parseFrame('\n')).toBeNull()
    expect(parseFrame(': keep-alive')).toBeNull()
  })
})

describe('splitFrames', () => {
  it('splits complete frames on the blank line', () => {
    const [frames, remainder] = splitFrames('data: a\n\ndata: b\n\n')
    expect(frames).toEqual(['data: a', 'data: b'])
    expect(remainder).toBe('')
  })

  it('keeps a trailing partial frame in the remainder rather than emitting it', () => {
    const [frames, remainder] = splitFrames('data: {"type":"start"}\n\ndata: {"type":"pro')
    expect(frames).toEqual(['data: {"type":"start"}'])
    expect(remainder).toBe('data: {"type":"pro')
  })

  it('emits nothing while no frame has terminated yet', () => {
    const [frames, remainder] = splitFrames('data: {"type":"star')
    expect(frames).toEqual([])
    expect(remainder).toBe('data: {"type":"star')
  })

  it('handles an empty buffer', () => {
    expect(splitFrames('')).toEqual([[], ''])
  })

  it('treats a blank frame between two events as its own empty frame', () => {
    const [frames, remainder] = splitFrames('data: a\n\n\n\ndata: b\n\n')
    expect(frames).toEqual(['data: a', '', 'data: b'])
    expect(remainder).toBe('')
  })
})

describe('runScanStream', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  it('posts the system prompt to the streaming endpoint', async () => {
    fetch.mockResolvedValue(streamResponse([frame({ type: 'start', total: 13 })]))
    const signal = new AbortController().signal

    await runScanStream('you are a helpful bot', { ...handlers(), signal })

    expect(fetch).toHaveBeenCalledTimes(1)
    const [url, init] = fetch.mock.calls[0]
    expect(url).toBe(SCAN_STREAM_URL)
    expect(init.method).toBe('POST')
    expect(init.headers).toMatchObject({
      'Content-Type': 'application/json',
      Accept: 'text/event-stream',
    })
    expect(JSON.parse(init.body)).toEqual({ system_prompt: 'you are a helpful bot' })
    expect(init.signal).toBe(signal)
  })

  it('routes each event type to its own callback', async () => {
    const h = handlers()
    fetch.mockResolvedValue(
      streamResponse([
        frame({ type: 'start', total: 2 }),
        frame({
          type: 'progress',
          current: 1,
          total: 2,
          attack_id: 'pi_001',
          owasp_category: 'LLM01',
        }),
        frame({
          type: 'progress',
          current: 2,
          total: 2,
          attack_id: 'sd_004',
          owasp_category: 'LLM06',
        }),
        frame({ type: 'done', result: DONE_RESULT }),
      ]),
    )

    await runScanStream('prompt', h)

    expect(h.onStart).toHaveBeenCalledTimes(1)
    expect(h.onStart).toHaveBeenCalledWith(expect.objectContaining({ total: 2 }))
    expect(h.onProgress).toHaveBeenCalledTimes(2)
    expect(h.onProgress.mock.calls.map(([e]) => e.owasp_category)).toEqual(['LLM01', 'LLM06'])
    // onDone receives the unwrapped result, not the envelope.
    expect(h.onDone).toHaveBeenCalledWith(DONE_RESULT)
    expect(h.onError).not.toHaveBeenCalled()
  })

  it('passes an error frame message through to onError', async () => {
    const h = handlers()
    fetch.mockResolvedValue(
      streamResponse([frame({ type: 'error', message: 'the analyzer key is missing.' })]),
    )

    await runScanStream('prompt', h)

    expect(h.onError).toHaveBeenCalledWith('the analyzer key is missing.')
    expect(h.onDone).not.toHaveBeenCalled()
  })

  it('falls back to a generic message when an error frame carries none', async () => {
    const h = handlers()
    fetch.mockResolvedValue(streamResponse([frame({ type: 'error' })]))

    await runScanStream('prompt', h)

    expect(h.onError).toHaveBeenCalledWith('the scan ended with an error.')
  })

  it('reassembles a frame that arrives split across two chunks', async () => {
    const h = handlers()
    const whole = frame({
      type: 'progress',
      current: 4,
      total: 13,
      attack_id: 'pi_002',
      owasp_category: 'LLM01',
    })
    const cut = Math.floor(whole.length / 2)
    fetch.mockResolvedValue(streamResponse([whole.slice(0, cut), whole.slice(cut)]))

    await runScanStream('prompt', h)

    expect(h.onProgress).toHaveBeenCalledTimes(1)
    expect(h.onProgress).toHaveBeenCalledWith(
      expect.objectContaining({ current: 4, total: 13, attack_id: 'pi_002' }),
    )
  })

  it('does not emit a frame while it is still incomplete', async () => {
    const h = handlers()
    // Two reads; only after the second does the first frame terminate.
    fetch.mockResolvedValue(
      streamResponse(['data: {"type":"start",', ' "total":13}\n\ndata: {"type":"progr']),
    )

    await runScanStream('prompt', h)

    expect(h.onStart).toHaveBeenCalledTimes(1)
    // The dangling `data: {"type":"progr` is flushed at stream end, but it is not
    // valid JSON, so parseFrame returns null and nothing is dispatched.
    expect(h.onProgress).not.toHaveBeenCalled()
    expect(h.onError).not.toHaveBeenCalled()
  })

  it('flushes a final frame that arrives without its trailing blank line', async () => {
    const h = handlers()
    fetch.mockResolvedValue(
      streamResponse([`data: ${JSON.stringify({ type: 'done', result: DONE_RESULT })}`]),
    )

    await runScanStream('prompt', h)

    expect(h.onDone).toHaveBeenCalledWith(DONE_RESULT)
  })

  it('reassembles a multi-byte character split across chunks', async () => {
    const h = handlers()
    const bytes = new TextEncoder().encode(frame({ type: 'error', message: 'café closed' }))
    // Cut inside the two-byte "é" so the decoder has to hold it across reads.
    const split = bytes.indexOf(0xc3) + 1
    fetch.mockResolvedValue(byteResponse([bytes.slice(0, split), bytes.slice(split)]))

    await runScanStream('prompt', h)

    expect(h.onError).toHaveBeenCalledWith('café closed')
  })

  it('ignores malformed, empty and unknown-type frames without throwing', async () => {
    const h = handlers()
    fetch.mockResolvedValue(
      streamResponse([
        'data: {"type":"start"\n\n', // broken JSON
        '\n\n', // empty frame
        ': keep-alive\n\n', // comment only
        frame({ type: 'heartbeat' }), // unknown type
        frame({ nope: true }), // no type at all
        frame({ type: 'done', result: DONE_RESULT }),
      ]),
    )

    await expect(runScanStream('prompt', h)).resolves.toBeUndefined()

    expect(h.onStart).not.toHaveBeenCalled()
    expect(h.onProgress).not.toHaveBeenCalled()
    expect(h.onError).not.toHaveBeenCalled()
    expect(h.onDone).toHaveBeenCalledWith(DONE_RESULT)
  })

  it('tolerates a caller that supplies no handlers at all', async () => {
    fetch.mockResolvedValue(
      streamResponse([frame({ type: 'start', total: 1 }), frame({ type: 'done', result: {} })]),
    )

    await expect(runScanStream('prompt')).resolves.toBeUndefined()
  })

  it('stops silently when fetch is aborted before the response arrives', async () => {
    const h = handlers()
    const controller = new AbortController()
    fetch.mockRejectedValue(abortError())
    controller.abort()

    await runScanStream('prompt', { ...h, signal: controller.signal })

    expect(h.onError).not.toHaveBeenCalled()
    expect(h.onDone).not.toHaveBeenCalled()
  })

  it('stops silently when the abort lands mid-stream', async () => {
    const h = handlers()
    const controller = new AbortController()
    fetch.mockResolvedValue(failingResponse([frame({ type: 'start', total: 13 })], abortError()))

    await runScanStream('prompt', { ...h, signal: controller.signal })

    // Events that already landed stay; the abort itself is not an error.
    expect(h.onStart).toHaveBeenCalledTimes(1)
    expect(h.onError).not.toHaveBeenCalled()
    expect(h.onDone).not.toHaveBeenCalled()
  })

  it('reports a friendly message when the backend is unreachable', async () => {
    const h = handlers()
    fetch.mockRejectedValue(new TypeError('Failed to fetch'))

    await runScanStream('prompt', h)

    expect(h.onError).toHaveBeenCalledTimes(1)
    expect(h.onError.mock.calls[0][0]).toContain(API_URL)
    expect(h.onError.mock.calls[0][0]).toContain('could not reach the scanner')
  })

  it('reports a friendly message when the stream tears mid-scan', async () => {
    const h = handlers()
    fetch.mockResolvedValue(
      failingResponse([frame({ type: 'start', total: 13 })], new TypeError('network error')),
    )

    await runScanStream('prompt', h)

    expect(h.onStart).toHaveBeenCalledTimes(1)
    expect(h.onError.mock.calls[0][0]).toContain('could not reach the scanner')
  })

  it('surfaces the status code when the server rejects the request', async () => {
    const h = handlers()
    fetch.mockResolvedValue(streamResponse([], { ok: false, status: 429 }))

    await runScanStream('prompt', h)

    expect(h.onError).toHaveBeenCalledWith('the server returned status 429.')
  })

  it('errors when the response carries no body to read', async () => {
    const h = handlers()
    fetch.mockResolvedValue(streamResponse([], { status: 204, body: false }))

    await runScanStream('prompt', h)

    expect(h.onError).toHaveBeenCalledWith('the server returned status 204.')
  })
})
