// Provenance footer (issue #2): a visitor must be able to see exactly what
// judged their prompt. Pure render tests against a fixture payload — no network,
// no scan, no API spend.
import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import ResultsView from './ResultsView.jsx'

/** The shape serialize_scan_result returns, trimmed to what this view needs. */
function makeResult(provenance) {
  return {
    scan_id: 'web-abc123',
    attacks_total: 1,
    summary: {
      by_status: { held: 1 },
      by_owasp_category: { LLM01: 0 },
      by_severity: {},
    },
    results: [
      {
        attack_id: 'PS-LLM01-001',
        name: 'Direct instruction override',
        owasp_category: 'LLM01',
        severity: 'high',
        status: 'held',
        judged_by: 'claude_analyzer',
      },
    ],
    ...(provenance === undefined ? {} : { provenance }),
  }
}

const PROVENANCE = {
  promptshield_version: '0.5.0',
  attack_library_version: '1.1.0',
  target_model: 'gpt-4o-mini-2024-07-18',
  judge_models: { claude_analyzer: 'claude-sonnet-4-6' },
  recorded_at: '2026-09-21T12:00:00+00:00',
}

const footer = () => screen.getByRole('region', { name: /what judged this prompt/i })

describe('provenance footer', () => {
  it('names the exact target model that answered the attacks', () => {
    render(<ResultsView result={makeResult(PROVENANCE)} onReset={() => {}} />)
    expect(within(footer()).getByText('gpt-4o-mini-2024-07-18')).toBeInTheDocument()
  })

  it('names the exact judge model that produced the verdicts', () => {
    render(<ResultsView result={makeResult(PROVENANCE)} onReset={() => {}} />)
    expect(within(footer()).getByText('claude-sonnet-4-6')).toBeInTheDocument()
  })

  it('shows the attack set and PromptShield versions', () => {
    render(<ResultsView result={makeResult(PROVENANCE)} onReset={() => {}} />)
    const scope = within(footer())
    expect(scope.getByText('v1.1.0')).toBeInTheDocument()
    expect(scope.getByText('v0.5.0')).toBeInTheDocument()
  })

  it('renders the timestamp as a machine-readable <time>', () => {
    render(<ResultsView result={makeResult(PROVENANCE)} onReset={() => {}} />)
    const time = within(footer()).getByText(/2026-09-21T12:00:00/)
    expect(time.tagName).toBe('TIME')
    expect(time).toHaveAttribute('dateTime', expect.stringContaining('2026-09-21T12:00:00'))
  })

  it('lists every judge when more than one produced verdicts', () => {
    render(
      <ResultsView
        result={makeResult({
          ...PROVENANCE,
          judge_models: {
            claude_analyzer: 'claude-sonnet-4-6',
            gemini_analyzer: 'gemini-2.0-flash-001',
          },
        })}
        onReset={() => {}}
      />,
    )
    const scope = within(footer())
    expect(scope.getByText('claude-sonnet-4-6')).toBeInTheDocument()
    expect(scope.getByText('gemini-2.0-flash-001')).toBeInTheDocument()
    expect(scope.getByText(/^Judges$/)).toBeInTheDocument()
  })

  it('renders nothing when the backend sent no provenance', () => {
    // An older backend must not break the results view.
    render(<ResultsView result={makeResult(undefined)} onReset={() => {}} />)
    expect(
      screen.queryByRole('region', { name: /what judged this prompt/i }),
    ).not.toBeInTheDocument()
  })

  it('omits only the rows the payload is missing', () => {
    render(
      <ResultsView
        result={makeResult({
          promptshield_version: '0.5.0',
          attack_library_version: '1.1.0',
          target_model: null,
          judge_models: {},
          recorded_at: null,
        })}
        onReset={() => {}}
      />,
    )
    const scope = within(footer())
    expect(scope.getByText('v1.1.0')).toBeInTheDocument()
    expect(scope.queryByText(/^Target model$/)).not.toBeInTheDocument()
    expect(scope.queryByText(/^Judge$/)).not.toBeInTheDocument()
    expect(scope.queryByText(/^Scanned at$/)).not.toBeInTheDocument()
  })

  it('drops an unparseable timestamp without taking the footer down', () => {
    render(
      <ResultsView
        result={makeResult({ ...PROVENANCE, recorded_at: 'not-a-date' })}
        onReset={() => {}}
      />,
    )
    const scope = within(footer())
    expect(scope.getByText('gpt-4o-mini-2024-07-18')).toBeInTheDocument()
    expect(scope.queryByText(/^Scanned at$/)).not.toBeInTheDocument()
  })
})
