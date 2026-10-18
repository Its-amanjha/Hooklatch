import { signedHeaders, isTcpAddress } from './signing.js';
import express from 'express';
import * as http from 'node:http';
import { createWebhookMiddleware } from '../../src/adapters/express.js';

function request(app: express.Express, path: string, body: string, headers: Record<string, string> = {}): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const server = http.createServer(app);
    server.listen(0, () => {
      const addr = server.address();

      if (!isTcpAddress(addr)) throw new Error('Expected TCP server address');
      const port = addr.port;

      const req = http.request({ hostname: '127.0.0.1', port, path, method: 'POST', headers: { 'content-length': String(Buffer.byteLength(body)), ...headers } }, (res) => {
        let data = '';
        res.on('data', (c: Buffer) => { data += c; });
        res.on('end', () => { server.close(); resolve({ status: res.statusCode ?? 0, body: data }); });
      });

      req.on('error', (e) => { server.close(); reject(e); });
      req.write(body);
      req.end();
    });
  });
}

test('returns 400 on verification failure', async () => {
  const app = express();
  app.use(createWebhookMiddleware({ provider: 'github', secrets: ['s'] }));
  app.use((_req, res) => res.status(200).send('ok'));
  const r = await request(app, '/', '{}');
  expect(r.status).toBe(400);
});

test('sets req.webhook and calls next on success', async () => {
  const app = express();
  app.use(createWebhookMiddleware({ provider: 'github', secrets: ['s'] }));
  app.use((req, res) => res.status(200).send(String(req.webhook?.rawBody.byteLength)));
  const r = await request(app, '/', 'hi', signedHeaders('hi'));
  expect(r.status).toBe(200);
  expect(r.body).toBe('2');
});

test('accepts captured Buffer body', async () => {
  const app = express();
  app.use(express.raw({ type: '*/*' }));
  app.use(createWebhookMiddleware({ provider: 'github', secrets: ['s'] }));
  app.use((_req, res) => res.status(200).send('ok'));
  const r = await request(app, '/', 'hi', { 'content-type': 'application/octet-stream', ...signedHeaders('hi') });
  expect(r.status).toBe(200);
});

test('rejects parsed JSON body', async () => {
  const app = express();
  app.use(express.json());
  app.use(createWebhookMiddleware({ provider: 'github', secrets: ['s'] }));
  app.use((_req, res) => res.status(200).send('ok'));
  const r = await request(app, '/', '{"a":1}', { 'content-type': 'application/json' });
  expect(r.status).toBe(500);
});

test('returns 413 on overflow', async () => {
  const app = express();
  app.use(createWebhookMiddleware({ provider: 'github', secrets: ['s'], maxBodyBytes: 1 }));
  app.use((_req, res) => res.status(200).send('ok'));
  const r = await request(app, '/', 'hello');
  expect(r.status).toBe(413);
});

