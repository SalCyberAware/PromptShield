// Backend wiring. The endpoint contract lives in one place.
import pkg from '../../package.json'

export const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'
export const SCAN_STREAM_PATH = '/api/scan/stream'
export const SCAN_STREAM_URL = `${API_URL}${SCAN_STREAM_PATH}`
export const GITHUB_URL = 'https://github.com/SalCyberAware/PromptShield'
// Single source of truth: frontend/package.json "version". Bump it there only.
export const APP_VERSION = `v${pkg.version}`
