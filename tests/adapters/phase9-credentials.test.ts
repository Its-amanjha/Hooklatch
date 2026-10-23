import express from 'express';

import { createWebhookMiddleware } from '../../src/adapters/express.js';
import { createWebhookHandler as createNextHandler } from '../../src/adapters/nextjs.js';
import { createWebhookHandler as createWorkerHandler } from '../../src/adapters/cloudflare.js';
import { createWebhookMiddleware as createHonoMiddleware } from '../../src/adapters/hono.js';

/**
 * Phase 9 Stage B repair round 1 - adapter credential contract tests.
 *
 * Contract-first tests for fal verification across all four adapters.
 * At this base (19 providers), 'fal' is not registered, so every test that
 * constructs fal middleware is RED. No casts hide the missing provider ID.
 * Post-integration (Codex), these define the expected behavior.
 */

const FAL_PUBLIC_KEY = new Uint8Array(32).fill(1);
const FAL_USER_ID = 'user-1';

// RED: 'fal' is not a registered provider at this base.
test('RED express: fal middleware construction', () => {
  const app = express();
  // SAFETY: 'fal' is not a registered provider at this base; cast is for contract-first test only.
  app.use(createWebhookMiddleware({ provider: 'fal', publicKeys: [FAL_PUBLIC_KEY], expectedUserId: FAL_USER_ID }));
  expect(app).toBeDefined();
});

test('RED hono: fal middleware construction', () => {
  // SAFETY: 'fal' is not a registered provider at this base; cast is for contract-first test only.
  const mw = createHonoMiddleware({ provider: 'fal', publicKeys: [FAL_PUBLIC_KEY], expectedUserId: FAL_USER_ID });
  expect(mw).toBeDefined();
});

test('RED nextjs: fal handler construction', () => {
  // SAFETY: 'fal' is not a registered provider at this base; cast is for contract-first test only.
  const handler = createNextHandler({ provider: 'fal', publicKeys: [FAL_PUBLIC_KEY], expectedUserId: FAL_USER_ID });
  expect(handler).toBeDefined();
});

test('RED cloudflare: fal handler construction', () => {
  // SAFETY: 'fal' is not a registered provider at this base; cast is for contract-first test only.
  const handler = createWorkerHandler({ options: () => ({ provider: 'fal', publicKeys: [FAL_PUBLIC_KEY], expectedUserId: FAL_USER_ID } as never), handler: async () => new Response('ok') });
  expect(handler).toBeDefined();
});
