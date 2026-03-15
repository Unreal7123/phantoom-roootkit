// playwright.config.ts
import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir:   './tests/e2e',
  timeout:   30000,
  retries:   1,
  reporter:  [['list'], ['html', { outputFolder: 'tests/e2e/report' }]],
  use: {
    actionTimeout:    8000,
    navigationTimeout: 15000,
    screenshot: 'only-on-failure',
    video:      'retain-on-failure',
    trace:      'retain-on-failure',
  },
  projects: [
    {
      name: 'electron',
      testMatch: '**/*.spec.ts',
    }
  ]
});
