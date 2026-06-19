// The rich results view. Renders the honest, status-aware result that
// serialize_scan_result (backend slice 3a) returns. No backend calls here.

// Display order by importance. Held is rendered last and quietly.
const STATUS_ORDER = ['vulnerable', 'needs_review', 'not_ai_judged', 'error', 'held']

const STATUS_META = {
  vulnerable: { label: 'Got through', cls: 'is-vulnerable', mark: '!' },
  needs_review: { label: 'Needs review', cls: 'is-review', mark: '?' },
  not_ai_judged: { label: 'Not AI-judged', cls: 'is-unjudged', mark: '~' },
  error: { label: 'Could not test', cls: 'is-error', mark: '×' },
  held: { label: 'Held', cls: 'is-held', mark: '✓' },
}

const SEVERITY_CLS = {
  critical: 'is-critical',
  high: 'is-high',
  medium: 'is-medium',
  low: 'is-low',
}

const ANALYZER_LABELS = {
  claude_analyzer: 'Claude',
  gemini_analyzer: 'Gemini',
  pattern_analyzer: 'Pattern floor',
  none: 'none',
}

// The six OWASP LLM categories the demo can test against a bare system prompt.
const TESTED_CATEGORIES = [
  ['LLM01', 'Prompt injection'],
  ['LLM02', 'Insecure output handling'],
  ['LLM06', 'Sensitive information disclosure'],
  ['LLM08', 'Excessive agency'],
  ['LLM09', 'Overreliance'],
  ['LLM10', 'Model theft'],
]

function analyzerLabel(name) {
  return ANALYZER_LABELS[name] || name
}

function buildHeadline(byStatus, total) {
  const vulnerable = byStatus.vulnerable || 0
  const needsReview = byStatus.needs_review || 0
  const notJudged = (byStatus.not_ai_judged || 0) + (byStatus.error || 0) + needsReview

  if (vulnerable > 0) {
    return {
      tone: 'is-bad',
      headline: `${vulnerable} of ${total} attacks got through.`,
      caveat: '',
    }
  }
  if (notJudged === 0) {
    return {
      tone: 'is-good',
      headline: `Held against all ${total} attacks, every one AI-judged.`,
      caveat: '',
    }
  }
  return {
    tone: 'is-mixed',
    headline: 'Held against every attack we could judge.',
    caveat: `${notJudged} of ${total} could not be conclusively judged.`,
  }
}

export default function ResultsView({ result, onReset }) {
  const summary = result.summary || {}
  const byStatus = summary.by_status || {}
  const total = result.attacks_total ?? result.results.length
  const { tone, headline, caveat } = buildHeadline(byStatus, total)
  const needsReview = byStatus.needs_review || 0

  const ordered = [...result.results].sort(
    (a, b) => STATUS_ORDER.indexOf(a.status) - STATUS_ORDER.indexOf(b.status),
  )
  const active = ordered.filter((r) => r.status !== 'held')
  const held = ordered.filter((r) => r.status === 'held')

  return (
    <div className="ps-results">
      <div className={`ps-results__headline ${tone}`} aria-live="polite">
        <p className="ps-results__lead">{headline}</p>
        {caveat && <p className="ps-results__caveat">{caveat}</p>}
        {needsReview > 0 && (
          <p className="ps-results__review">
            {needsReview} flagged for manual review.
          </p>
        )}
      </div>

      <Breakdowns summary={summary} />

      <div className="ps-findings">
        {active.map((r) => (
          <FindingCard key={r.attack_id} finding={r} />
        ))}

        {held.length > 0 && (
          <details className="ps-held-group">
            <summary>Held against {held.length} attacks</summary>
            <div className="ps-held-group__body">
              {held.map((r) => (
                <FindingCard key={r.attack_id} finding={r} quiet />
              ))}
            </div>
          </details>
        )}
      </div>

      <div className="ps-actions">
        <button type="button" className="ps-scan-btn" onClick={onReset}>
          Scan another prompt
        </button>
      </div>
    </div>
  )
}

function StatusBadge({ status }) {
  const meta = STATUS_META[status] || STATUS_META.error
  return (
    <span className={`ps-badge ${meta.cls}`}>
      <span className="ps-badge__mark" aria-hidden="true">
        {meta.mark}
      </span>
      {meta.label}
    </span>
  )
}

function FindingCard({ finding, quiet = false }) {
  const {
    name,
    attack_id,
    owasp_category,
    severity,
    status,
    judged_by,
    confidence_band,
    confidence_score,
    response_excerpt,
    verdicts = [],
    aggregate = {},
  } = finding

  const reasons = verdicts
    .filter((v) => v.reasoning)
    .map((v) => `${analyzerLabel(v.analyzer)}: ${v.reasoning}`)

  return (
    <article className={`ps-finding ${quiet ? 'is-quiet' : ''}`}>
      <header className="ps-finding__head">
        <div className="ps-finding__title">
          <span className="ps-finding__name">{name}</span>
          <span className="ps-finding__id">{attack_id}</span>
        </div>
        <StatusBadge status={status} />
      </header>

      <div className="ps-finding__tags">
        <span className="ps-owasp-chip">{owasp_category}</span>
        <span className={`ps-sev ${SEVERITY_CLS[severity] || 'is-low'}`}>
          {severity}
        </span>
      </div>

      {(status === 'vulnerable' || status === 'needs_review') && (
        <div className="ps-finding__body">
          {reasons.map((line, i) => (
            <p className="ps-finding__reason" key={i}>
              {line}
            </p>
          ))}
          <p className="ps-finding__prov">
            {confidence_band && (
              <span>
                {confidence_band} confidence
                {typeof confidence_score === 'number'
                  ? ` (${confidence_score.toFixed(2)})`
                  : ''}
              </span>
            )}
            <AggregateSlot aggregate={aggregate} judgedBy={judged_by} />
          </p>
        </div>
      )}

      {status === 'not_ai_judged' && (
        <p className="ps-finding__note">
          Pattern floor only. No AI verdict was produced for this attack, so treat
          it with caution.
        </p>
      )}

      {status === 'error' && (
        <p className="ps-finding__note">
          This attack could not be tested. The target did not return a usable
          response.
        </p>
      )}

      {response_excerpt && (
        <details className="ps-evidence">
          <summary>Show the model reply</summary>
          <pre className="ps-evidence__body">{response_excerpt}</pre>
        </details>
      )}
    </article>
  )
}

function AggregateSlot({ aggregate, judgedBy }) {
  const agreement = aggregate.agreement
  if (agreement === 'agree') {
    return <span className="ps-finding__agree">Judges agree</span>
  }
  if (agreement === 'disagree') {
    return <span className="ps-finding__disagree">Judges disagree, review</span>
  }
  // Single-judge mode: name the one judge.
  return <span>Judged by {analyzerLabel(judgedBy)}</span>
}

function Breakdowns({ summary }) {
  const byOwasp = summary.by_owasp_category || {}
  const bySeverity = summary.by_severity || {}
  const severityOrder = ['critical', 'high', 'medium', 'low']
  const severityEntries = severityOrder.filter((s) => bySeverity[s])

  return (
    <div className="ps-breakdowns">
      <section className="ps-breakdown">
        <h3 className="ps-breakdown__title">OWASP coverage</h3>
        <p className="ps-breakdown__hint">Tested 6 of the 10 OWASP LLM categories.</p>
        <div className="ps-chip-row">
          {TESTED_CATEGORIES.map(([code, label]) => {
            const count = byOwasp[code] || 0
            return (
              <span
                className={`ps-chip ${count > 0 ? 'is-hit' : ''}`}
                key={code}
                title={label}
              >
                {code}
                <span className="ps-chip__count">{count}</span>
              </span>
            )
          })}
        </div>
        <p className="ps-breakdown__note">
          Not applicable to a bare system prompt: supply chain, training data
          poisoning, and plugin design need a live application to test. We never
          count those as passed.
        </p>
      </section>

      {severityEntries.length > 0 && (
        <section className="ps-breakdown">
          <h3 className="ps-breakdown__title">Severity of findings</h3>
          <div className="ps-chip-row">
            {severityEntries.map((sev) => (
              <span className={`ps-sev ${SEVERITY_CLS[sev]}`} key={sev}>
                {sev}
                <span className="ps-chip__count">{bySeverity[sev]}</span>
              </span>
            ))}
          </div>
        </section>
      )}
    </div>
  )
}
