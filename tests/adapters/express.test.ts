/* eslint-disable @typescript-eslint/no-explicit-any */
import { jest } from '@jest/globals';

await jest.unstable_mockModule('../../src/index.js', () => {
  const verify = jest.fn();
  return { verify, createVerifier: () => verify };
});

const expressMod = await import('express');
const express = expressMod.default;
const http = await import('node:http');
const { createWebhookMiddleware } = await import('../../src/adapters/express.js');
const { verify } = await import('../../src/index.js');
const verifyMock = verify as jest.MockedFunction<typeof verify>;

function request(app: any, path: string, body: string, headers: Record<string, string> = {}): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const server = http.createServer(app);
    server.listen(0, () => {
      const addr = server.address();
      const port = typeof addr === 'object' && addr ? (addr as any).port : 0;
      const req = http.request({ hostname: '127.0.0.1', port, path, method: 'POST', headers: { 'content-length': String(Buffer.byteLength(body)), ...headers } }, (res: any) => {
        let data = '';
        res.on('data', (c: any) => { data += c; });
        res.on('end', () => { server.close(); resolve({ status: res.statusCode ?? 0, body: data }); });
      });
      req.on('error', (e: any) => { server.close(); reject(e); });
      req.write(body);
      req.end();
    });
  });
}

beforeEach(() => verifyMock.mockReset());

test('returns 400 on verification failure', async () => {
  verifyMock.mockResolvedValue({ ok: false, provider: 'github', reason: 'invalid-signature', message: 'bad' });
  const app = express();
  app.use(createWebhookMiddleware({ provider: 'github', secrets: ['s'] }));
  app.use((_req: any, res: any) => res.status(200).send('ok'));
  const r = await request(app, '/', '{}');
  expect(r.status).toBe(400);
});

test('sets req.webhook and calls next on success', async () => {
  const raw = Buffer.from('hi');
  verifyMock.mockResolvedValue({ ok: true, provider: 'github', rawBody: new Uint8Array(raw), identity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] } });
  const app = express();
  app.use(createWebhookMiddleware({ provider: 'github', secrets: ['s'] }));
  app.use((req: any, res: any) => res.status(200).send(String(req.webhook?.rawBody.byteLength)));
  const r = await request(app, '/', 'hi');
  expect(r.status).toBe(200);
  expect(r.body).toBe('2');
});

test('accepts captured Buffer body', async () => {
  const raw = Buffer.from('hi');
  verifyMock.mockResolvedValue({ ok: true, provider: 'github', rawBody: new Uint8Array(raw), identity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] } });
  const app = express();
  app.use(express.raw({ type: '*/*' }));
  app.use(createWebhookMiddleware({ provider: 'github', secrets: ['s'] }));
  app.use((_req: any, res: any) => res.status(200).send('ok'));
  const r = await request(app, '/', 'hi', { 'content-type': 'application/octet-stream' });
  expect(r.status).toBe(200);
});

test('rejects parsed JSON body', async () => {
  const app = express();
  app.use(express.json());
  app.use(createWebhookMiddleware({ provider: 'github', secrets: ['s'] }));
  app.use((_req: any, res: any) => res.status(200).send('ok'));
  const r = await request(app, '/', '{"a":1}', { 'content-type': 'application/json' });
  expect(r.status).toBe(500);
});

test('returns 413 on overflow', async () => {
  const app = express();
  app.use(createWebhookMiddleware({ provider: 'github', secrets: ['s'], maxBodyBytes: 1 }));
  app.use((_req: any, res: any) => res.status(200).send('ok'));
  const r = await request(app, '/', 'hello');
  expect(r.status).toBe(413);
});

