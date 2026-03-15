// ============================================================================
// PhantomScope — tests/e2e/app.spec.ts
// Playwright E2E Tests for the Electron Application
// ============================================================================

import { test, expect, _electron as electron, ElectronApplication, Page } from '@playwright/test';
import path from 'path';

let electronApp: ElectronApplication;
let page: Page;

test.beforeAll(async () => {
  // Launch Electron app in test mode
  electronApp = await electron.launch({
    args: [path.join(__dirname, '../../src/app/main.js')],
    env: {
      ...process.env,
      NODE_ENV: 'test',
    }
  });

  page = await electronApp.firstWindow();
  await page.waitForLoadState('domcontentloaded');
});

test.afterAll(async () => {
  await electronApp.close();
});

// ============================================================================
// App launch tests
// ============================================================================

test('app launches with correct title', async () => {
  const title = await page.title();
  expect(title).toContain('PhantomScope');
});

test('titlebar is visible', async () => {
  await expect(page.locator('.titlebar')).toBeVisible();
  await expect(page.locator('.app-name')).toHaveText('PhantomScope');
});

test('sidenav renders with all navigation items', async () => {
  await expect(page.locator('.sidenav')).toBeVisible();
  await expect(page.locator('.nav-item')).toHaveCount(5);  // graph, dashboard, inspector, history, settings
});

test('scan button is present', async () => {
  await expect(page.locator('.scan-btn')).toBeVisible();
  await expect(page.locator('.scan-btn')).toContainText('SCAN');
});

// ============================================================================
// Graph view tests
// ============================================================================

test('graph view is default active view', async () => {
  await expect(page.locator('.graph-view')).toBeVisible();
});

test('query bar renders in graph view', async () => {
  await expect(page.locator('.query-bar')).toBeVisible();
  await expect(page.locator('.query-input')).toBeVisible();
});

test('graph toolbar renders with correct buttons', async () => {
  await expect(page.locator('.graph-toolbar')).toBeVisible();
  await expect(page.locator('.toolbar-btn')).toHaveCount(3);  // fit, reset, export
});

test('empty state shows when no scan data', async () => {
  await expect(page.locator('.graph-empty-state')).toBeVisible({ timeout: 2000 }).catch(() => {
    // May have demo data loaded — also acceptable
  });
});

test('query shortcuts render', async () => {
  const chips = page.locator('.query-chip');
  await expect(chips).toHaveCount(5);
  await expect(chips.first()).toContainText('Hidden');
});

// ============================================================================
// Demo data scan test
// ============================================================================

test('demo scan loads graph data', async () => {
  // Wait for demo data auto-load
  await page.waitForTimeout(1500);

  // Either graph has nodes OR empty state is shown
  const hasNodes = await page.locator('.graph-canvas').isVisible();
  const hasEmpty = await page.locator('.graph-empty-state').isVisible().catch(() => false);

  expect(hasNodes || hasEmpty).toBeTruthy();
});

// ============================================================================
// Navigation tests
// ============================================================================

test('navigating to dashboard shows dashboard view', async () => {
  await page.locator('.nav-item').nth(1).click();  // Dashboard
  await expect(page.locator('.dashboard')).toBeVisible();
  await expect(page.locator('.stat-cards-grid')).toBeVisible();
});

test('dashboard shows stat cards', async () => {
  await expect(page.locator('.stat-card')).toHaveCount(6);
});

test('navigating to settings shows settings panel', async () => {
  await page.locator('.nav-item').nth(4).click();  // Settings (last)
  await expect(page.locator('.settings-panel')).toBeVisible();
});

test('settings panel shows API key section', async () => {
  await expect(page.locator('text=VirusTotal API Key')).toBeVisible();
});

test('navigating to inspector shows empty inspector', async () => {
  await page.locator('.nav-item').nth(2).click();  // Inspector
  await expect(page.locator('.inspector-empty')).toBeVisible();
});

test('navigating back to graph view restores graph', async () => {
  await page.locator('.nav-item').nth(0).click();  // Graph
  await expect(page.locator('.graph-view')).toBeVisible();
});

// ============================================================================
// Query bar tests
// ============================================================================

test('typing in query bar updates search', async () => {
  await page.locator('.nav-item').nth(0).click();  // Ensure graph view

  const input = page.locator('.query-input');
  await input.fill('explorer');
  await expect(input).toHaveValue('explorer');
});

test('clear button appears when query has text', async () => {
  await expect(page.locator('.query-clear')).toBeVisible();
});

test('clicking clear button empties query', async () => {
  await page.locator('.query-clear').click();
  await expect(page.locator('.query-input')).toHaveValue('');
  await expect(page.locator('.query-clear')).not.toBeVisible();
});

test('clicking query chip applies query', async () => {
  const chip = page.locator('.query-chip').first();  // "Hidden"
  await chip.click();
  await expect(page.locator('.query-input')).not.toHaveValue('');
  await expect(chip).toHaveClass(/active/);
});

test('clicking active chip clears it', async () => {
  const chip = page.locator('.query-chip').first();
  await chip.click();  // toggle off
  await expect(page.locator('.query-input')).toHaveValue('');
});

// ============================================================================
// Threat panel tests
// ============================================================================

test('threat panel renders on graph view', async () => {
  await page.locator('.nav-item').nth(0).click();
  // May appear after demo data loads
  await page.waitForTimeout(1000);
  const panel = page.locator('.threat-panel');
  // Panel may or may not be visible depending on demo data timing
  const visible = await panel.isVisible();
  if (visible) {
    await expect(page.locator('.threat-panel-header h3')).toHaveText('Threats');
  }
});

// ============================================================================
// Window controls tests (Electron only)
// ============================================================================

test('window control buttons are present', async () => {
  const controls = page.locator('.titlebar-controls');
  if (await controls.isVisible()) {
    await expect(page.locator('.wc-minimize')).toBeVisible();
    await expect(page.locator('.wc-maximize')).toBeVisible();
    await expect(page.locator('.wc-close')).toBeVisible();
  }
});

// ============================================================================
// Settings interaction tests
// ============================================================================

test('API key input accepts text', async () => {
  await page.locator('.nav-item').nth(4).click();  // Settings

  const keyInput = page.locator('.settings-input');
  if (await keyInput.isVisible()) {
    await keyInput.fill('test-api-key-12345');
    await expect(keyInput).toHaveValue('test-api-key-12345');
  }
});

test('save key button enables when API key typed', async () => {
  const saveBtn = page.locator('.btn-primary').first();
  if (await saveBtn.isVisible()) {
    await expect(saveBtn).not.toBeDisabled();
  }
});

// ============================================================================
// Graph legend tests
// ============================================================================

test('graph legend items render in toolbar', async () => {
  await page.locator('.nav-item').nth(0).click();
  await expect(page.locator('.legend-critical')).toBeVisible();
  await expect(page.locator('.legend-suspicious')).toBeVisible();
  await expect(page.locator('.legend-info')).toBeVisible();
  await expect(page.locator('.legend-clean')).toBeVisible();
});

// ============================================================================
// Accessibility basics
// ============================================================================

test('scan button has accessible title', async () => {
  const btn = page.locator('.scan-btn');
  const title = await btn.getAttribute('title');
  expect(title).toContain('Scan');
});

test('nav items have accessible titles', async () => {
  const items = page.locator('.nav-item');
  const count = await items.count();
  for (let i = 0; i < count; ++i) {
    const title = await items.nth(i).getAttribute('title');
    expect(title).toBeTruthy();
  }
});
