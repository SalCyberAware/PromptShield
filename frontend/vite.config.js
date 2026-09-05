import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
// Dev server defaults to port 5173, which the backend CORS allowlist already trusts.
// `defineConfig` comes from vitest/config so the `test` block below type-checks and
// the build config stays in one file.
export default defineConfig({
  plugins: [react()],
  test: {
    // jsdom for the React Testing Library specs; the pure scanStream specs do not
    // need it but sharing one environment keeps the config short.
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.js'],
    include: ['src/**/*.test.{js,jsx}'],
    // No `globals: true` on purpose: every spec imports describe/it/expect/vi from
    // vitest explicitly, so eslint needs no extra global allowlist.
    globals: false,
  },
})
