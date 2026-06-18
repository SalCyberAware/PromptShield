import { GITHUB_URL } from '../lib/config.js'

export default function Footer() {
  return (
    <footer className="ps-footer">
      <div className="ps-container ps-footer__inner">
        <span>Server-side keys</span>
        <span className="ps-footer__sep" aria-hidden="true">
          /
        </span>
        <span>Zero data retention</span>
        <span className="ps-footer__sep" aria-hidden="true">
          /
        </span>
        <a href={GITHUB_URL} target="_blank" rel="noreferrer">
          Open source
        </a>
      </div>
    </footer>
  )
}
