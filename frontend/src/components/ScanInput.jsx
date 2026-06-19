import { useEffect, useRef, useState } from 'react'
import { HARDENED_PROMPT, LEAKY_PROMPT } from '../lib/examplePrompt.js'
import { runScanStream } from '../lib/scanStream.js'
import ConfidenceStrip from './ConfidenceStrip.jsx'
import ResultsView from './ResultsView.jsx'

const PLACEHOLDER =
  'Paste the system prompt you want to test. The text that tells your AI how to behave, what to refuse, and what to keep secret.'

export default function ScanInput() {
  const [prompt, setPrompt] = useState('')
  const [status, setStatus] = useState('idle') // idle | scanning | done | error
  const [progress, setProgress] = useState(null) // { current, total, owasp }
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  const abortRef = useRef(null)

  // Abort an in-flight scan if the component unmounts.
  useEffect(() => () => abortRef.current?.abort(), [])

  const isEmpty = prompt.trim().length === 0
  const isScanning = status === 'scanning'

  function startScan() {
    const controller = new AbortController()
    abortRef.current = controller

    setStatus('scanning')
    setProgress({ current: 0, total: 13, owasp: '' })
    setResult(null)
    setError('')

    runScanStream(prompt, {
      signal: controller.signal,
      onStart: (event) =>
        setProgress({ current: 0, total: event.total, owasp: '' }),
      onProgress: (event) =>
        setProgress({
          current: event.current,
          total: event.total,
          owasp: event.owasp_category,
        }),
      onDone: (scanResult) => {
        setResult(scanResult)
        setStatus('done')
      },
      onError: (message) => {
        setError(message)
        setStatus('error')
      },
    })
  }

  function handleCancel() {
    abortRef.current?.abort()
    setStatus('idle')
    setProgress(null)
  }

  function handleReset() {
    setStatus('idle')
    setProgress(null)
    setResult(null)
    setError('')
  }

  function handleUseExample(text) {
    setPrompt(text)
    handleReset()
  }

  return (
    <section className="ps-card" aria-label="System prompt scanner">
      <div className="ps-label-row">
        <label className="ps-label" htmlFor="system-prompt">
          System prompt
        </label>
        <div className="ps-example-btns">
          <button
            type="button"
            className="ps-ghost-btn"
            onClick={() => handleUseExample(LEAKY_PROMPT)}
            disabled={isScanning}
          >
            Try a leaky prompt
          </button>
          <button
            type="button"
            className="ps-ghost-btn"
            onClick={() => handleUseExample(HARDENED_PROMPT)}
            disabled={isScanning}
          >
            Try a hardened prompt
          </button>
        </div>
      </div>

      <textarea
        id="system-prompt"
        className="ps-textarea"
        placeholder={PLACEHOLDER}
        value={prompt}
        onChange={(event) => setPrompt(event.target.value)}
        spellCheck="false"
        disabled={isScanning}
      />

      <div className="ps-counter">
        {prompt.length.toLocaleString()} characters
      </div>

      {status === 'idle' && (
        <>
          <ConfidenceStrip />
          <div className="ps-actions">
            <button
              type="button"
              className="ps-scan-btn"
              onClick={startScan}
              disabled={isEmpty}
            >
              Scan prompt
            </button>
          </div>
        </>
      )}

      {status === 'scanning' && progress && (
        <ScanProgress progress={progress} onCancel={handleCancel} />
      )}

      {status === 'done' && result && (
        <ResultsView result={result} onReset={handleReset} />
      )}

      {status === 'error' && (
        <ScanError message={error} onRetry={startScan} onReset={handleReset} />
      )}
    </section>
  )
}

function ScanProgress({ progress, onCancel }) {
  const { current, total, owasp } = progress
  const pct = total > 0 ? Math.round((current / total) * 100) : 0

  return (
    <div className="ps-progress" aria-live="polite">
      <div className="ps-progress__head">
        <span>
          Running attack {current} of {total}
        </span>
        {owasp && <span className="ps-progress__owasp">OWASP {owasp}</span>}
      </div>
      <div
        className="ps-progress__track"
        role="progressbar"
        aria-valuenow={current}
        aria-valuemin={0}
        aria-valuemax={total}
      >
        <div className="ps-progress__fill" style={{ width: `${pct}%` }} />
      </div>
      <div className="ps-actions">
        <button type="button" className="ps-ghost-btn" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </div>
  )
}

function ScanError({ message, onRetry, onReset }) {
  return (
    <div className="ps-error" role="alert">
      <p className="ps-error__headline">Scan failed: {message}</p>
      <div className="ps-actions">
        <button type="button" className="ps-scan-btn" onClick={onRetry}>
          Try again
        </button>
        <button type="button" className="ps-ghost-btn" onClick={onReset}>
          Start over
        </button>
      </div>
    </div>
  )
}
