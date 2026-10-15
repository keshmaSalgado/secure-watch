import { test, expect } from '@playwright/test';

test.describe('SecureWatch End-to-End Test Suite', () => {

  test.beforeEach(async ({ page }) => {
    // Navigate to base URL
    await page.goto('/');
  });

  test('should display login screen with demo credentials when unauthenticated', async ({ page }) => {
    await expect(page).toHaveTitle(/SecureWatch/i);
    await expect(page.locator('text=SECUREWATCH')).toBeVisible();
    await expect(page.locator('text=Enterprise Threat Detection & Incident Response Platform')).toBeVisible();

    // Verify quick fill demo accounts exist
    await expect(page.locator('button:has-text("Admin")')).toBeVisible();
    await expect(page.locator('button:has-text("SecAdmin")')).toBeVisible();
    await expect(page.locator('button:has-text("Analyst")')).toBeVisible();
    await expect(page.locator('button:has-text("Auditor")')).toBeVisible();
  });

  test('should authenticate successfully with Super Admin credentials', async ({ page }) => {
    // Click quick fill Admin
    await page.click('button:has-text("Admin")');
    await page.click('button:has-text("Authenticate & Launch")');

    // Should navigate to dashboard
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('text=Executive Security Overview')).toBeVisible();
    await expect(page.locator('text=Total Telemetry Events')).toBeVisible();
    await expect(page.locator('text=Threat Detections')).toBeVisible();
    await expect(page.locator('text=Critical Incidents')).toBeVisible();
  });

  test('should open attack simulator modal and launch attack scenario', async ({ page }) => {
    // Log in
    await page.click('button:has-text("Admin")');
    await page.click('button:has-text("Authenticate & Launch")');
    await expect(page).toHaveURL(/.*dashboard/);

    // Open Simulator
    const simButton = page.locator('button:has-text("Attack Simulator")');
    await expect(simButton).toBeVisible();
    await simButton.click();

    // Modal should be visible
    await expect(page.locator('text=Cyber Attack Simulator')).toBeVisible();
    await expect(page.locator('text=Credential Stuffing / Brute Force')).toBeVisible();

    // Trigger simulation
    await page.click('button:has-text("Simulate Credential Attack")');
    await expect(page.locator('text=Simulation execution completed')).toBeVisible();
  });

  test('should navigate to Live Monitoring and display stream status', async ({ page }) => {
    await page.click('button:has-text("Admin")');
    await page.click('button:has-text("Authenticate & Launch")');

    // Navigate to Live Monitoring
    await page.click('a:has-text("Live Monitoring")');
    await expect(page).toHaveURL(/.*monitoring/);
    await expect(page.locator('text=Real-Time Telemetry Stream')).toBeVisible();
    await expect(page.locator('text=Connected')).toBeVisible();
  });

  test('should navigate to Incident Management and display incidents', async ({ page }) => {
    await page.click('button:has-text("Admin")');
    await page.click('button:has-text("Authenticate & Launch")');

    await page.click('a:has-text("Incident Response")');
    await expect(page).toHaveURL(/.*incidents/);
    await expect(page.locator('text=Security Incidents')).toBeVisible();
  });

  test('should open AI Security Copilot and interact with assistant', async ({ page }) => {
    await page.click('button:has-text("Admin")');
    await page.click('button:has-text("Authenticate & Launch")');

    await page.click('a:has-text("AI Assistant")');
    await expect(page).toHaveURL(/.*ai-assistant/);
    await expect(page.locator('text=AI Security Copilot')).toBeVisible();
    await expect(page.locator('text=Cyber Security LLM Agent')).toBeVisible();

    // Verify prompt buttons
    const promptBtn = page.locator('button:has-text("Critical incidents today?")');
    await expect(promptBtn).toBeVisible();
    await promptBtn.click();

    // Verify response arrives
    await expect(page.locator('.copilot-response, .chat-message')).toBeVisible();
  });

});

