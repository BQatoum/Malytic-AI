import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // Proxy /api to backend in development so CORS preflight isn't needed
      '/api': { target: 'http://localhost:8000', changeOrigin: true },
    },
  },
})
