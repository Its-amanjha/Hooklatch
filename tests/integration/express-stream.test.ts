import { isTcpAddress } from '../adapters/signing.js';
import { createHmac } from 'node:crypto';
import express from 'express';
import { createWebhookMiddleware } from '../../src/adapters/express.js';

test('Express rejects drained streams, accepts captured bytes, and verifies genuine empty bodies', async () => {
  const secret = 'express_stream_synthetic_secret';
  const app = express();
  let drainedHandlerRan = false;
  const middleware = createWebhookMiddleware({ provider: 'github', secrets: [secret] });
  app.post('/drained', async (req, _res, next) => {
    for await (const _chunk of req) { /* prior middleware discards the bytes */ }

    next();
  }, middleware, (_req, res) => { drainedHandlerRan = true; res.send('accepted'); });
  app.post('/captured', async (req, _res, next) => {
    const chunks: Buffer[] = [];

    for await (const chunk of req) {
      if (!(chunk instanceof Uint8Array)) throw new Error('Expected raw stream bytes');
      chunks.push(Buffer.from(chunk));
    }

    req.body = Buffer.concat(chunks);
    next();
  }, middleware, (_req, res) => res.send('captured accepted'));
  app.post('/empty', middleware, (_req, res) => res.send('empty accepted'));
  const server = app.listen(0, '127.0.0.1');
  await new Promise<void>((resolve, reject) => {
    server.once('listening', resolve);
    server.once('error', reject);
  });

  try {
    const address = server.address();

    if (!isTcpAddress(address)) throw new Error('Expected TCP address');
    const origin = `http://127.0.0.1:${address.port}`;

    const send = (path: string, body: string, signedBody = body) => fetch(`${origin}/${path}`, {
      method: 'POST', body,
      headers: { 'x-hub-signature-256': `sha256=${createHmac('sha256', secret).update(signedBody).digest('hex')}` },
    });

    const drained = await send('drained', 'unsigned original bytes', '');
    expect(drained.status).toBe(500);
    expect(await drained.text()).toBe('Internal Server Error');
    expect(drainedHandlerRan).toBe(false);
    const captured = await send('captured', 'correct captured bytes');
    expect(captured.status).toBe(200);
    expect(await captured.text()).toBe('captured accepted');
    const empty = await send('empty', '');
    expect(empty.status).toBe(200);
    expect(await empty.text()).toBe('empty accepted');
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});
