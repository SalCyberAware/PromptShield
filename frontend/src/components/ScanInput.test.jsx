import { act } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import ScanInput from './ScanInput.jsx'
import { LEAKY_PROMPT } from '../lib/examplePrompt.js'
import { runScanStream } from '../lib/scanStream.js'

// The stream client has its own unit tests; here it is a seam. Mocking it lets
// each SSE event be delivered on demand so the card's four states can be driven
// without a network or a fake ReadableStream.
vi.mock('../lib/scanStream.js', () => ({ runScanStream: vi.fn() }))

const RESULT = {
  attacks_total: 2,
  summary: {
    by_status: { vulnerable: 1, held: 1 },
    by_owasp_category: { LLM01: 1, LLM06: 1 },
    by_severity: { high: 1 },
  },
  results: [
    {
      attack_id: 'pi_001',
      name: 'Direct instruction override',
      owasp_category: 'LLM01',
      severity: 'high',
      status: 'vulnerable',
      judged_by: 'claude_analyzer',
      confidence_band: 'high',
      confidence_score: 0.91,
      response_excerpt: 'Sure, my instructions are...',
      verdicts: [{ analyzer: 'claude_analyzer', reasoning: 'the model disclosed its prompt' }],
      aggregate: { agreement: 'agree' },
    },
    {
      attack_id: 'sd_004',
      name: 'Credential fishing',
      owasp_category: 'LLM06',
      severity: 'low',
      status: 'held',
      judged_by: 'claude_analyzer',
      verdicts: [],
      aggregate: {},
    },
  ],
}

/** The handlers object ScanInput passed to the mocked runScanStream. */
const lastHandlers = () => runScanStream.mock.calls.at(-1)[1]

function typePrompt(text = 'you are a helpful bot') {
  fireEvent.change(screen.getByLabelText('System prompt'), { target: { value: text } })
}

function startScan() {
  fireEvent.click(screen.getByRole('button', { name: 'Scan prompt' }))
}

describe('ScanInput', () => {
  beforeEach(() => {
    runScanStream.mockReset()
  })

  it('disables the scan button until the prompt has content', () => {
    render(<ScanInput />)
    const button = screen.getByRole('button', { name: 'Scan prompt' })

    expect(button).toBeDisabled()

    typePrompt()
    expect(button).toBeEnabled()

    // Whitespace alone does not count as a prompt.
    typePrompt('   ')
    expect(button).toBeDisabled()
  })

  it('loads an example prompt into the textarea and counts its characters', () => {
    render(<ScanInput />)

    fireEvent.click(screen.getByRole('button', { name: 'Try a leaky prompt' }))

    expect(screen.getByLabelText('System prompt')).toHaveValue(LEAKY_PROMPT)
    expect(
      screen.getByText(`${LEAKY_PROMPT.length.toLocaleString()} characters`),
    ).toBeInTheDocument()
  })

  it('sends the prompt to runScanStream and shows progress as events arrive', () => {
    render(<ScanInput />)
    typePrompt('scan me')
    startScan()

    expect(runScanStream).toHaveBeenCalledTimes(1)
    expect(runScanStream.mock.calls[0][0]).toBe('scan me')

    const { onStart, onProgress } = lastHandlers()
    act(() => onStart({ type: 'start', total: 13 }))
    expect(screen.getByText('Running attack 0 of 13')).toBeInTheDocument()

    act(() =>
      onProgress({ type: 'progress', current: 5, total: 13, owasp_category: 'LLM01' }),
    )
    expect(screen.getByText('Running attack 5 of 13')).toBeInTheDocument()
    expect(screen.getByText('OWASP LLM01')).toBeInTheDocument()
    expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '5')
  })

  it('renders the results view when the done event arrives', () => {
    render(<ScanInput />)
    typePrompt()
    startScan()

    act(() => lastHandlers().onDone(RESULT))

    expect(screen.getByText('1 of 2 attacks got through.')).toBeInTheDocument()
    expect(screen.getByText('Direct instruction override')).toBeInTheDocument()
    expect(screen.getByText('Held against 1 attacks')).toBeInTheDocument()
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument()
  })

  it('shows the error state with a retry that runs the scan again', () => {
    render(<ScanInput />)
    typePrompt()
    startScan()

    act(() => lastHandlers().onError('the server returned status 429.'))

    expect(screen.getByRole('alert')).toHaveTextContent(
      'Scan failed: the server returned status 429.',
    )

    fireEvent.click(screen.getByRole('button', { name: 'Try again' }))
    expect(runScanStream).toHaveBeenCalledTimes(2)
  })

  it('aborts the in-flight scan when cancelled and returns to idle', () => {
    render(<ScanInput />)
    typePrompt()
    startScan()

    const { signal } = lastHandlers()
    expect(signal.aborted).toBe(false)

    act(() => lastHandlers().onStart({ type: 'start', total: 13 }))
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))

    expect(signal.aborted).toBe(true)
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Scan prompt' })).toBeInTheDocument()
  })

  it('aborts the in-flight scan when the card unmounts', () => {
    const { unmount } = render(<ScanInput />)
    typePrompt()
    startScan()

    const { signal } = lastHandlers()
    unmount()

    expect(signal.aborted).toBe(true)
  })
})
