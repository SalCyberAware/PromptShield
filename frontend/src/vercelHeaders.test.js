// Guards frontend/vercel.json: the security headers Vercel serves on every
// path, and the Report-Only CSP that must allow the Railway API and Google Fonts.
import { describe, expect, it } from 'vitest'
import vercel from '../vercel.json'

const API_ORIGIN = 'https://promptshield-production-1846.up.railway.app'

const allPathsHeaders = () => {
  const rule = vercel.headers.find((entry) => entry.source === '/(.*)')
  expect(rule).toBeDefined()
  return Object.fromEntries(rule.headers.map(({ key, value }) => [key, value]))
}

const cspDirectives = () => {
  const csp = allPathsHeaders()['Content-Security-Policy-Report-Only']
  expect(csp).toBeDefined()
  return Object.fromEntries(
    csp
      .split(';')
      .map((part) => part.trim().split(/\s+/))
      .filter((tokens) => tokens[0])
      .map(([name, ...sources]) => [name, sources]),
  )
}

describe('vercel.json security headers', () => {
  it('sets the baseline headers on every path', () => {
    const headers = allPathsHeaders()
    expect(headers['X-Content-Type-Options']).toBe('nosniff')
    expect(headers['X-Frame-Options']).toBe('DENY')
    expect(headers['Referrer-Policy']).toBe('strict-origin-when-cross-origin')
    expect(headers['Strict-Transport-Security']).toMatch(/^max-age=\d+/)
  })

  it('ships the CSP in Report-Only mode, not enforcing yet', () => {
    expect(allPathsHeaders()['Content-Security-Policy']).toBeUndefined()
  })

  it('lets the page call the Railway API', () => {
    expect(cspDirectives()['connect-src']).toContain(API_ORIGIN)
  })

  it('allows Google Fonts stylesheets and font files', () => {
    const directives = cspDirectives()
    expect(directives['style-src']).toContain('https://fonts.googleapis.com')
    expect(directives['font-src']).toContain('https://fonts.gstatic.com')
  })

  it('keeps scripts same-origin and blocks framing', () => {
    const directives = cspDirectives()
    expect(directives['script-src']).toEqual(["'self'"])
    expect(directives['frame-ancestors']).toEqual(["'none'"])
  })
})
