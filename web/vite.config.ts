import { resolve } from 'path'

import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// The build is emitted into the Python package so it ships inside the wheel and
// is served by FastAPI at "/". During `vite dev`, /api is proxied to the local
// `auditor serve` backend on 127.0.0.1:8765.
export default defineConfig({
  plugins: [react()],
  base: '/',
  build: {
    outDir: resolve(__dirname, '../src/auditor/web/static'),
    emptyOutDir: true,
  },
  server: {
    proxy: { '/api': 'http://127.0.0.1:8765' },
  },
})
