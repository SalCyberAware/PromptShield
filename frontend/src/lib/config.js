// Backend wiring. The actual scan stream call lands in the next slice; this is
// here so the endpoint contract lives in one place.
export const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'
export const SCAN_STREAM_PATH = '/api/scan/stream'
export const GITHUB_URL = 'https://github.com/SalCyberAware/PromptShield'
export const APP_VERSION = 'v0.5.0'
