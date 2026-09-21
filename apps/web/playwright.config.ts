import { defineConfig, devices } from '@playwright/test'
import { fileURLToPath } from 'node:url'
import { loadEnv } from 'vite'
import { developmentWebConfig } from './dev-server.mjs'

const environment = loadEnv('development', fileURLToPath(new URL('../..', import.meta.url)), '')

export default defineConfig({
  testDir: './tests/browser',
  fullyParallel: false,
  workers: 1,
  reporter: 'list',
  use: { baseURL: process.env.PLAYWRIGHT_BASE_URL || developmentWebConfig(environment).publicURL, trace: 'retain-on-failure', screenshot: 'only-on-failure' },
  projects: [
    { name: 'desktop', use: { ...devices['Desktop Chrome'], channel: 'chrome', viewport: { width: 1440, height: 960 } } },
    { name: 'mobile', use: { ...devices['iPhone 13'], defaultBrowserType: 'chromium', channel: 'chrome' } },
  ],
})
