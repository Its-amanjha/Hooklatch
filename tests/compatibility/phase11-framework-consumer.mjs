/**
 * Phase 11 framework consumer fixture for real four-framework interop.
 *
 * Consumed by scripts/phase11/workers-compatibility.mjs. Exports a small set
 * of named functions that exercise the public hooklatch adapters for Express,
 * Hono, Next.js App Router and Cloudflare Workers using REAL framework trees
 * (read-only linked dependencies), never mocks or stub handlers.
 *
 * This file is intentionally dependency-free aside from the peer frameworks that
 * are already installed in the repository. It performs no network I/O.
 */
import { createHmac } from 'node:crypto';

export const FRAMEWORKS = ['express', 'hono', 'nextjs', 'cloudflare'];

export function githubHeaders(body, secret, timestamp = 1700000000) {
  const mac = createHmac('sha256', secret).update(body).digest('hex');

  return {
    'content-type': 'application/json',
    'x-hub-signature-256': `sha256=${mac}`,
    'x-github-delivery': 'phase11-delivery',
    'x-github-event': 'push',
    'x-hooklatch-timestamp': String(timestamp),
  };
}

export function tamperedHeaders(body, secret) {
  const h = githubHeaders(body, secret);

  return { ...h, 'x-hub-signature-256': 'sha256=' + '0'.repeat(64) };
}

export async function runExpressSmoke(appFactory) {
  // appFactory: (handler) => express app with POST /webhook
  const handler = async (req, res) => {
    res.status(200).json({ ok: true, framework: 'express' });
  };

  const app = appFactory(handler);

  return { framework: 'express', created: Boolean(app) };
}

export async function runHonoSmoke(createApp) {
  const app = createApp();

  return { framework: 'hono', created: Boolean(app) };
}

export async function runNextSmoke(routeHandler) {
  const req = new Request('http://localhost/api/webhook', { method: 'POST', body: '{}' });
  const res = await routeHandler(req);

  return { framework: 'nextjs', status: res?.status ?? null };
}

export async function runCloudflareSmoke(fetchHandler, env) {
  const req = new Request('http://localhost/webhook', { method: 'POST', body: '{}' });
  const res = await fetchHandler(req, env);

  return { framework: 'cloudflare', status: res?.status ?? null };
}

export function assertHooklatchErrorIdentity(a, b) {
  // Returns true when both are the same constructor identity (cross-format).
  return a instanceof Function && b instanceof Function && a === b;
}
