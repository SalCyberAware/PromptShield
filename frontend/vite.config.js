import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
// Dev server defaults to port 5173, which the backend CORS allowlist already trusts.
export default defineConfig({
  plugins: [react()],
})
