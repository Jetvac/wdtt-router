import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import { readFileSync } from 'node:fs'

// MOCK=1 serves anonymised API responses from mock/fixtures.json, so the UI
// can be developed without a panel. Otherwise /api is proxied to PANEL.
function mockApi(): Plugin {
  const fixtures = JSON.parse(readFileSync(new URL('./mock/fixtures.json', import.meta.url), 'utf-8'))
  const lastJob = Object.keys(fixtures).filter((k) => /^\/api\/jobs\/\d+$/.test(k))[0]
  return {
    name: 'mock-api',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const url = req.url || ''
        if (!url.startsWith('/api/')) return next()
        res.setHeader('Content-Type', 'application/json')
        if (url === '/api/me') return res.end(JSON.stringify({ username: 'admin', csrf: 'mock', version: 'mock' }))
        if (req.method !== 'GET') return res.end(JSON.stringify(lastJob ? { job_id: Number(lastJob.split('/').pop()) } : { ok: true }))
        const key = Object.keys(fixtures).find((k) => k === url) || Object.keys(fixtures).find((k) => k.split('?')[0] === url.split('?')[0])
        if (!key) {
          res.statusCode = 404
          return res.end(JSON.stringify({ error: 'нет данных в mock' }))
        }
        res.end(JSON.stringify(fixtures[key]))
      })
    },
  }
}

export default defineConfig({
  plugins: [react(), ...(process.env.MOCK ? [mockApi()] : [])],
  build: { outDir: 'dist', emptyOutDir: true, chunkSizeWarningLimit: 2000, sourcemap: false },
  server: { port: 5173, proxy: process.env.MOCK ? undefined : { '/api': { target: process.env.PANEL || 'https://127.0.0.1:8443', secure: false } } },
})
