import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
// Dev server defaults to port 5173, which the backend CORS allowlist already trusts.
// `defineConfig` comes from vitest/config so the `test` block below type-checks and
// the build config stays in one file.

// Bakes the commit being deployed into the served HTML as
// <meta name="build-commit" content="...">, so a post-deploy check can ask a
// static build what it is running. Vercel sets VERCEL_GIT_COMMIT_SHA at build
// time for git-connected deploys, which requires "Enable access to System
// Environment Variables" in the Vercel project settings; GIT_COMMIT_SHA is a
// platform-neutral override. Neither is set locally, which is what "unknown"
// means -- not an error.
//
// index.html rather than a separate /version.json on purpose: index.html is the
// document whose staleness is the actual failure, because it names the
// content-hashed bundles. A version.json can be served fresh while index.html
// is stale, which would let the check pass on a stale site.
const buildCommitMeta = () => ({
  name: 'build-commit-meta',
  transformIndexHtml: () => [
    {
      tag: 'meta',
      attrs: {
        name: 'build-commit',
        content:
          process.env.VERCEL_GIT_COMMIT_SHA ||
          process.env.GIT_COMMIT_SHA ||
          'unknown',
      },
      injectTo: 'head',
    },
  ],
})

export default defineConfig({
  plugins: [react(), buildCommitMeta()],
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
