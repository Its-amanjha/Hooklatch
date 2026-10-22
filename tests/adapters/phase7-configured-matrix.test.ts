import { createHmac } from 'node:crypto';
import { createServer, request as nodeRequest } from 'node:http';
import express from 'express';
import { Hono } from 'hono';
import { createWebhookMiddleware as expressWebhook } from '../../src/adapters/express.js';
import { createWebhookMiddleware as honoWebhook } from '../../src/adapters/hono.js';
import { createWebhookHandler as nextWebhook } from '../../src/adapters/nextjs.js';
import { createWebhookHandler as workerWebhook } from '../../src/adapters/cloudflare.js';
import type { VerificationSuccess, VerifyOptions } from '../../src/index.js';
import { isTcpAddress } from './signing.js';

type Framework = 'express' | 'express-captured' | 'hono' | 'nextjs' | 'cloudflare';

interface HttpResult { readonly status: number; readonly body: string }

type Invoke = (headers: Readonly<Record<string, string>>) => Promise<HttpResult>;

const FRAMEWORKS: readonly Framework[] = ['express', 'express-captured', 'hono', 'nextjs', 'cloudflare'];
const BODY = new Uint8Array([0, 255, 128, 65]);
const NOW = 1700000100;
const SECRET = 'matrix-synthetic-secret-not-a-credential';
const POLAR_SECRET = `whsec_${Buffer.alloc(24, 66).toString('base64')}`;

function digest(key: string | Uint8Array, prefix: string, encoding: 'hex' | 'base64'): string {
  return createHmac('sha256', key).update(Buffer.concat([Buffer.from(prefix), Buffer.from(BODY)])).digest(encoding);
}

async function nodeCall(app: express.Express, headers: Readonly<Record<string, string>>): Promise<HttpResult> {
  const server = createServer(app);

  try {
    await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    const address = server.address();

    if (!isTcpAddress(address)) throw new Error('Expected a TCP listener');

    return await new Promise<HttpResult>((resolve, reject) => {
      const request = nodeRequest({ host: '127.0.0.1', port: address.port, method: 'POST',
        headers: { 'content-type': 'application/octet-stream', ...headers } }, (response) => {
        const chunks: Buffer[] = [];
        response.on('data', (chunk: Buffer) => chunks.push(chunk));
        response.once('error', reject);
        response.once('end', () => resolve({ status: response.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }));
      });

      request.once('error', reject);
      request.end(Buffer.from(BODY));
    });
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}

function endpoint(framework: Framework, options: VerifyOptions, received: VerificationSuccess[]): Invoke {
  const accept = (success: VerificationSuccess): Response => {
    received.push(success);

    return new Response('accepted');
  };

  if (framework === 'express' || framework === 'express-captured') {
    const app = express();

    if (framework === 'express-captured') app.use(express.raw({ type: 'application/octet-stream', inflate: false }));
    app.use(expressWebhook(options));
    app.use((request, response) => {
      if (request.webhook === undefined) throw new Error('Missing verified webhook');
      received.push(request.webhook);
      response.send('accepted');
    });

    return (headers) => nodeCall(app, headers);
  }

  if (framework === 'hono') {
    const app = new Hono();
    app.post('/', honoWebhook(options), (context) => {
      const success = context.get('webhook');

      if (success === undefined) throw new Error('Missing verified webhook');

      return accept(success);
    });

    return async (headers) => {
      const response = await app.request('https://hooklatch.test/', { method: 'POST', headers, body: new Uint8Array(BODY) });

      return { status: response.status, body: await response.text() };
    };
  }

  const next = framework === 'nextjs' ? nextWebhook({ ...options, handler: (_request, success) => accept(success) }) : undefined;
  const worker = workerWebhook({ options: () => options, handler: (_request, _env, _context, success) => accept(success) });

  return async (headers) => {
    const request = new Request('https://hooklatch.test/', { method: 'POST', headers, body: new Uint8Array(BODY) });
    const response = next === undefined ? await worker(request, {}, {}) : await next(request);

    return { status: response.status, body: await response.text() };
  };
}

interface ConfiguredCase {
  readonly name: string;
  readonly options: VerifyOptions;
  readonly wrong: VerifyOptions;
  readonly headers: Readonly<Record<string, string>>;
  readonly timestamp: number | null;
  readonly eventId: string | null;
}

function cases(): readonly ConfiguredCase[] {
  const grafanaBody: VerifyOptions = { provider: 'grafana', secrets: [SECRET], now: () => NOW,
    providerOptions: { mode: 'body', signatureHeader: 'x-matrix-signature' } };

  const grafanaTimestamped: VerifyOptions = { provider: 'grafana', secrets: [SECRET], now: () => NOW,
    providerOptions: { mode: 'timestamped', signatureHeader: 'x-matrix-signature', timestampHeader: 'x-matrix-timestamp' } };

  const current: VerifyOptions = { provider: 'polar', secrets: [POLAR_SECRET], now: () => NOW, providerOptions: { secretMode: 'current' } };
  const legacy: VerifyOptions = { provider: 'polar', secrets: [POLAR_SECRET], now: () => NOW, providerOptions: { secretMode: 'legacy' } };
  const canonical = { 'webhook-id': 'matrix-message', 'webhook-timestamp': String(NOW) };

  return [
    { name: 'Grafana body custom-header binding', options: grafanaBody,
      wrong: { ...grafanaBody, providerOptions: { mode: 'body' } },
      headers: { 'x-matrix-signature': digest(SECRET, '', 'hex'), 'x-grafana-alerting-signature': '0'.repeat(64),
        'x-matrix-timestamp': '9999999999' }, timestamp: null, eventId: null },
    { name: 'Grafana timestamped custom headers', options: grafanaTimestamped, wrong: grafanaBody,
      headers: { 'x-matrix-signature': digest(SECRET, `${NOW}:`, 'hex'), 'x-matrix-timestamp': String(NOW),
        'x-grafana-alerting-signature': '0'.repeat(64) }, timestamp: NOW, eventId: null },
    { name: 'Polar current', options: current, wrong: legacy,
      headers: { ...canonical, 'webhook-signature': `v1,${digest(Buffer.from(POLAR_SECRET.slice(6), 'base64'), `matrix-message.${NOW}.`, 'base64')}` },
      timestamp: NOW, eventId: 'matrix-message' },
    { name: 'Polar legacy', options: legacy, wrong: current,
      headers: { ...canonical, 'webhook-signature': `v1,${digest(POLAR_SECRET, `matrix-message.${NOW}.`, 'base64')}` },
      timestamp: NOW, eventId: 'matrix-message' },
  ];
}

describe.each(FRAMEWORKS)('%s configured public adapter', (framework) => {
  test.each(cases())('$name preserves exact bytes and authenticated identity', async (sample) => {
    const received: VerificationSuccess[] = [];
    const result = await endpoint(framework, sample.options, received)(sample.headers);
    expect(result).toEqual({ status: 200, body: 'accepted' });
    expect(received).toHaveLength(1);
    const success = received[0];

    if (success === undefined) throw new Error('Missing handler result');
    expect(success.provider).toBe(sample.options.provider);
    expect(success.rawBody).toEqual(BODY);
    expect(success.identity).toEqual({ deliveryId: null, eventId: sample.eventId, timestamp: sample.timestamp,
      authenticatedFields: sample.options.provider === 'polar' ? ['eventId', 'timestamp'] : sample.timestamp === null ? [] : ['timestamp'] });
  });

  test.each(cases())('$name rejects wrong layout/header/era without calling the handler', async (sample) => {
    const received: VerificationSuccess[] = [];
    const result = await endpoint(framework, sample.wrong, received)(sample.headers);
    expect(result).toEqual({ status: 400, body: 'Bad Request' });
    expect(received).toHaveLength(0);
  });

  test('retains custom Grafana configuration across repeated requests', async () => {
    const config = { mode: 'body' as const, signatureHeader: 'x-first-signature' };
    const received: VerificationSuccess[] = [];
    const call = endpoint(framework, { provider: 'grafana', secrets: [SECRET], providerOptions: config }, received);
    expect((await call({ 'x-first-signature': digest(SECRET, '', 'hex') })).status).toBe(200);
    config.signatureHeader = 'x-second-signature';
    expect((await call({ 'x-second-signature': digest(SECRET, '', 'hex') })).status).toBe(200);
    expect((await call({ 'x-first-signature': digest(SECRET, '', 'hex') })).status).toBe(400);
    expect(received).toHaveLength(2);
  });

  test('rejects a throwing configuration getter with a generic response before the handler', async () => {
    const config = { mode: 'body' as const };
    let reads = 0;
    Object.defineProperty(config, 'mode', { enumerable: true, get() {
      reads += 1;
      throw new Error('configuration-getter-sensitive-canary');
    } });
    const received: VerificationSuccess[] = [];
    const result = await endpoint(framework, { provider: 'grafana', secrets: [SECRET], providerOptions: config }, received)({});
    expect(result).toEqual({ status: 500, body: 'Internal Server Error' });
    expect(reads).toBe(1);
    expect(received).toHaveLength(0);
  });

  test('rejects a supplied own undefined header rather than defaulting it', async () => {
    const config = { mode: 'body' as const };
    Object.defineProperty(config, 'signatureHeader', { value: undefined, enumerable: true });
    const received: VerificationSuccess[] = [];
    const result = await endpoint(framework, { provider: 'grafana', secrets: [SECRET], providerOptions: config }, received)({});
    expect(result).toEqual({ status: 500, body: 'Internal Server Error' });
    expect(received).toHaveLength(0);
  });
});

test('Express captures the verification clock before its request stream is read', async () => {
  const app = express();
  let captured = false;
  let readAfterClock = false;
  let iteratorReads = 0;
  app.use((request, _response, next) => {
    const iterate = request[Symbol.asyncIterator].bind(request);
    Object.defineProperty(request, Symbol.asyncIterator, { get() {
      iteratorReads += 1;
      readAfterClock = captured;

      return iterate;
    } });
    next();
  });
  app.use(expressWebhook({ provider: 'grafana', secrets: [SECRET],
    providerOptions: { mode: 'timestamped', timestampHeader: 'x-clock' },
    now: () => {
      captured = true;

      return NOW;
    } }));
  app.use((_request, response) => response.send('accepted'));

  const result = await nodeCall(app, {
    'x-grafana-alerting-signature': digest(SECRET, `${NOW}:`, 'hex'), 'x-clock': String(NOW),
  });

  expect(result.status).toBe(200);
  expect(iteratorReads).toBeGreaterThan(0);
  expect(captured).toBe(true);
  expect(readAfterClock).toBe(true);
});

test('Express validates configuration before touching captured bytes or its async iterator', async () => {
  const app = express();
  let bodyReads = 0;
  let iteratorReads = 0;
  let configReads = 0;
  const config = { mode: 'body' as const };
  Object.defineProperty(config, 'mode', { enumerable: true, get() {
    configReads += 1;
    throw new Error('configuration-getter-sensitive-canary');
  } });
  app.use((request, _response, next) => {
    const iterate = request[Symbol.asyncIterator].bind(request);
    Object.defineProperty(request, 'body', { get() {
      bodyReads += 1;

      return Buffer.from(BODY);
    } });
    Object.defineProperty(request, Symbol.asyncIterator, { get() {
      iteratorReads += 1;

      return iterate;
    } });
    next();
  });
  app.use(expressWebhook({ provider: 'grafana', secrets: [SECRET], providerOptions: config }));
  const result = await nodeCall(app, {});
  expect(result).toEqual({ status: 500, body: 'Internal Server Error' });
  expect(configReads).toBe(1);
  expect(bodyReads).toBe(0);
  expect(iteratorReads).toBe(0);
});
