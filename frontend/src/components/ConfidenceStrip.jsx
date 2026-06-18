const ITEMS = ['13 attacks', '6 OWASP categories', 'Live results']

export default function ConfidenceStrip() {
  return (
    <div className="ps-strip">
      {ITEMS.map((label) => (
        <span className="ps-pill" key={label}>
          <span className="ps-pill__dot" aria-hidden="true" />
          {label}
        </span>
      ))}
    </div>
  )
}
