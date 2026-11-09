import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The Windows app's own screens (server list and setup). The app serves
// them under /_app/; everything else in its window comes from the panel.
export default defineConfig({
  plugins: [react()],
  base: '/_app/',
  build: {
    outDir: 'launcher/dist',
    emptyOutDir: false,
    chunkSizeWarningLimit: 2000,
    sourcemap: false,
    rollupOptions: { input: 'launcher.html' },
  },
})
