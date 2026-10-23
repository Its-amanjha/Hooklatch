import { createHmac } from 'node:crypto';
import * as http from 'node:http';
import express from 'express';

import { createWebhookMiddleware } from '../../src/adapters/express.js';
import { isTcpAddress } from './signing.js';

const GITHUB_SECRET = 'phase9-adapter-config-canary-secret';

function hmacHex(bytes: Uint8Array, secret: string): string {
  return createHmac('sha256', secret).update(bytes).digest('hex');
}

function githubSig(bytes: Uint8Array, secret: string): string {
  return `sha256=${hmacHex(bytes, secret)}`;
}

function toBytes(text: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(new TextEncoder().encode(text));
}

function sendRaw(app: express.Express, body: Uint8Array, headers: Record<string, string> = {}): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const server = http.createServer(app);
    server.listen(0, () => {
      const addr = server.address();

      if (!isTcpAddress(addr)) {
        server.close();
        reject(new Error('Expected TCP server address'));

        return;
      }

      const port = addr.port;

      const req = http.request(
        { hostname: '127.0.0.1', port, path: '/', method: 'POST', headers: { 'content-type': 'application/octet-stream', ...headers } },
        (res) => {
          let data = '';
          res.on('data', (c: Buffer) => { data += c; });
          res.on('end', () => { server.close(); resolve({ status: res.statusCode ?? 0, body: data }); });
        },
      );

      req.on('error', (e) => { server.close(); reject(e); });
      req.write(Buffer.from(body));
      req.end();
    });
  });
}

/**
 * Phase 9 Stage B adapter credential tests.
 *
 * Fal and Vercel are not yet registered providers (19 base). Configuration
 * propagation tests use 'github' as a registered proxy. Fal/Vercel-specific
 * adapter cases are RED at this base and are documented as expected.
 */

test('express adapter accepts providerOptions without breaking verification', async () => {
  const options = { provider: 'github' as const, secrets: [GITHUB_SECRET] };
  const app = express();
  app.use(createWebhookMiddleware(options));
  app.use((_req, res) => res.status(200).send('ok'));

  const body = toBytes('{"event":"test"}');
  const sig = githubSig(body, GITHUB_SECRET);

  const res = await sendRaw(app, body, { 'x-hub-signature-256': sig, 'content-length': String(body.byteLength) });

  expect(res.status).toBe(200);
});

test('express adapter rejects missing signature', async () => {
  const options = { provider: 'github' as const, secrets: [GITHUB_SECRET] };
  const app = express();
  app.use(createWebhookMiddleware(options));
  app.use((_req, res) => res.status(200).send('ok'));

  const body = toBytes('{"event":"test"}');

  const res = await sendRaw(app, body, { 'content-length': String(body.byteLength) });

  expect(res.status).toBe(400);
});
