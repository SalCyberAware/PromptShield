import { APP_VERSION, GITHUB_URL } from '../lib/config.js'

function ShieldMark() {
  return (
    <svg
      className="ps-wordmark__shield"
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M12 4 L18 6.2 V11 C18 14.8 15.5 18 12 19.4 C8.5 18 6 14.8 6 11 V6.2 Z"
        stroke="var(--color-accent)"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      <path
        d="M9.3 11.6 L11.2 13.5 L14.9 9.4"
        stroke="var(--color-accent)"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

export default function Header() {
  return (
    <header className="ps-header">
      <div className="ps-container ps-header__inner">
        <span className="ps-wordmark">
          <ShieldMark />
          PromptShield
        </span>
        <div className="ps-header__right">
          <span className="ps-version">{APP_VERSION}</span>
          <a
            className="ps-ghlink"
            href={GITHUB_URL}
            target="_blank"
            rel="noreferrer"
          >
            GitHub
          </a>
        </div>
      </div>
    </header>
  )
}
