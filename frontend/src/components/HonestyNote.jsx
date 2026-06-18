export default function HonestyNote() {
  return (
    <div className="ps-honesty">
      <span className="ps-honesty__mark" aria-hidden="true">
        [i]
      </span>
      <p>
        <strong>Some categories cannot be judged from a system prompt alone.</strong>{' '}
        Supply chain, training data poisoning, and plugin design need a live
        application to test. We show those as not applicable. We never count them
        as passed.
      </p>
    </div>
  )
}
