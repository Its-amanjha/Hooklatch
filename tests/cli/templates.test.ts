import { renderTemplate } from '../../src/cli/templates.js';

test('express template uses adapter and env placeholder', () => {
  const out = renderTemplate('stripe', 'express', { secretEnv: 'STRIPE_WEBHOOK_SECRET', bodyLimit: 1024 });
  expect(out).toContain("createWebhookMiddleware");
  expect(out).toContain("process.env.STRIPE_WEBHOOK_SECRET!");
  expect(out).toContain("maxBodyBytes: 1024");
});

test('nextjs template exports POST', () => {
  const out = renderTemplate('github', 'nextjs', { secretEnv: 'GITHUB_WEBHOOK_SECRET', bodyLimit: 2048 });
  expect(out).toContain("export const POST");
});

test('hono template exports middleware', () => {
  const out = renderTemplate('shopify', 'hono', { secretEnv: 'SHOPIFY_WEBHOOK_SECRET', bodyLimit: 4096 });
  expect(out).toContain("shopifyHonoWebhook");
});

test('cloudflare template uses env binding', () => {
  const out = renderTemplate('standard-webhooks', 'cloudflare', { secretEnv: 'STANDARD_WEBHOOKS_SECRET', bodyLimit: 8192 });
  expect(out).toContain("env.STANDARD_WEBHOOKS_SECRET");
});
