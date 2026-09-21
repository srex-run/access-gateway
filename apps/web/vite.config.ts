import { fileURLToPath, URL } from 'node:url'
import react from '@vitejs/plugin-react'
import { defineConfig, loadEnv } from 'vite'
import { developmentWebConfig } from './dev-server.mjs'

export default defineConfig(({ mode }) => {
  const envDir = fileURLToPath(new URL('../..', import.meta.url))
  const env = loadEnv(mode, envDir, '')
  const web = developmentWebConfig(env)
  return {
    envDir,
    plugins: [react()],
    resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },
    server: {
      host: web.host,
      port: web.port,
      allowedHosts: web.allowedHosts,
      strictPort: true,
      proxy: {
        '/api/v1': {
          target: env.ACCESS_GATEWAY_UPSTREAM || 'http://127.0.0.1:8080',
          changeOrigin: false,
          ws: true,
          xfwd: true,
        },
      },
    },
    build: {
      outDir: 'dist',
      sourcemap: false,
      rolldownOptions: {
        output: {
          entryFileNames: 'assets/app-[hash].js',
          chunkFileNames: 'assets/[name]-[hash].js',
          assetFileNames: 'assets/[name]-[hash][extname]',
        },
      },
    },
  }
})
