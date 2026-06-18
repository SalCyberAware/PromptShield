import { useState } from 'react'
import { EXAMPLE_PROMPT } from '../lib/examplePrompt.js'
import ConfidenceStrip from './ConfidenceStrip.jsx'

const PLACEHOLDER =
  'Paste the system prompt you want to test. The text that tells your AI how to behave, what to refuse, and what to keep secret.'

export default function ScanInput() {
  const [prompt, setPrompt] = useState('')
  const [note, setNote] = useState('')

  const isEmpty = prompt.trim().length === 0

  function handleScan() {
    // Placeholder for this slice. The SSE scan stream gets wired in the next one.
    setNote('Live scanning connects in the next update.')
  }

  function handleUseExample() {
    setPrompt(EXAMPLE_PROMPT)
    setNote('')
  }

  return (
    <section className="ps-card" aria-label="System prompt scanner">
      <div className="ps-label-row">
        <label className="ps-label" htmlFor="system-prompt">
          System prompt
        </label>
        <button
          type="button"
          className="ps-ghost-btn"
          onClick={handleUseExample}
        >
          Use example
        </button>
      </div>

      <textarea
        id="system-prompt"
        className="ps-textarea"
        placeholder={PLACEHOLDER}
        value={prompt}
        onChange={(event) => setPrompt(event.target.value)}
        spellCheck="false"
      />

      <div className="ps-counter">
        {prompt.length.toLocaleString()} characters
      </div>

      <ConfidenceStrip />

      <div className="ps-actions">
        <button
          type="button"
          className="ps-scan-btn"
          onClick={handleScan}
          disabled={isEmpty}
        >
          Scan prompt
        </button>
        {note && <span className="ps-status">{note}</span>}
      </div>
    </section>
  )
}
