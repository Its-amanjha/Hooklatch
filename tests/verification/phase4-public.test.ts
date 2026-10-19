import { createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { jest } from '@jest/globals';
import express from 'express';
import { Hono } from 'hono';
import { createWebhookMiddleware as createExpressMiddleware } from '../../src/adapters/express.js';
import { createWebhookMiddleware as createHonoMiddleware } from '../../src/adapters/hono.js';
import { createWebhookHandler as createNextHandler } from '../../src/adapters/nextjs.js';
import { createWebhookHandler as createWorkerHandler } from '../../src/adapters/cloudflare.js';
import { isTcpAddress } from '../adapters/signing.js';
import { createVerifier, verify, verifyRequest } from '../../src/index.js';
import { diagnose } from '../../src/diagnostics/index.js';
import { parseArgs } from '../../src/cli/args.js';
import type { HeaderInput, VerificationResult, VerifyOptions } from '../../src/types.js';
import type { FixtureCase } from './helpers.js';
import { fixtureBytes, fixtureOptions, isFixtureFile, representationsOf } from './helpers.js';

const PROVIDERS = ['dodo-payments', 'gitlab', 'replicate', 'workos'] as const;
const ENTRYPOINTS = ['verify', 'verifyRequest', 'createVerifier'] as const;

type EntryPoint = (typeof ENTRYPOINTS)[number];

function casesFor(provider: string): readonly FixtureCase[] {
  const parsed: unknown = JSON.parse(readFileSync(new URL(`../fixtures/${provider}.json`, import.meta.url), 'utf8'));

  if (!isFixtureFile(parsed)) throw new Error('Invalid provider fixture');

  return parsed.cases;
}

function firstPositive(provider: string): FixtureCase {
  const fixture = casesFor(provider).find((entry) => entry.expected.ok);

  if (!fixture) throw new Error('Missing positive fixture');

  return fixture;
}

function isHeaderList(value: string | readonly string[]): value is readonly string[] {
  return Array.isArray(value);
}

function webHeaders(input: HeaderInput): Headers {
  if (input instanceof Headers) return new Headers(input);

  const headers = new Headers();

  if (Array.isArray(input)) {
    for (const [name, value] of input) headers.append(name, value);
  } else {
    for (const [name, value] of Object.entries(input)) {
      if (value === undefined) continue;

      if (isHeaderList(value)) {
        for (const part of value) headers.append(name, part);
      } else headers.append(name, value);
    }
  }

  return headers;
}

async function invoke(entrypoint: EntryPoint, rawBody: Uint8Array, headers: HeaderInput, options: VerifyOptions): Promise<VerificationResult> {
  if (entrypoint === 'verify') return verify({ rawBody, headers }, options);

  if (entrypoint === 'createVerifier') return createVerifier(options)({ rawBody, headers });

  return verifyRequest(new Request('https://hooklatch.test/webhook', {
    method: 'POST', headers: webHeaders(headers), body: new Uint8Array(rawBody),
  }), options);
}

describe.each(PROVIDERS)('%s Phase 4 public fixture qualification', (provider) => {
  const fixtures = casesFor(provider);

  test('pins corpus cardinality and unique IDs', () => {
    expect(fixtures).toHaveLength({ 'dodo-payments': 31, gitlab: 34, replicate: 31, workos: 58 }[provider]);
    expect(new Set(fixtures.map((entry) => entry.id)).size).toBe(fixtures.length);
  });

  describe.each(ENTRYPOINTS)('%s', (entrypoint) => {
    test.each(fixtures)('$id has exact outcomes across record, tuples and Headers', async (fixture) => {
      const body = fixtureBytes(fixture);

      for (const headers of representationsOf(fixture)) {
        const result = await invoke(entrypoint, body, headers, fixtureOptions(provider, fixture));
        expect(result.ok).toBe(fixture.expected.ok);
        expect(result.provider).toBe(provider);

        if (result.ok) {
          expect(fixture.expected.identity).toBeDefined();
          expect(result.identity).toEqual(fixture.expected.identity);
          expect(result.rawBody).toEqual(body);
        } else expect(result.reason).toBe(fixture.expected.reason);
      }
    });
  });
});

describe.each(ENTRYPOINTS)('%s WorkOS clock and freshness', (entrypoint) => {
  const fixture = firstPositive('workos');
  const timestamp = fixture.expected.identity?.timestamp;

  if (timestamp === null || timestamp === undefined) throw new Error('Missing WorkOS timestamp');

  test.each([-180.001, -180, 180, 180.001])('omitted 180-second window at drift %f', async (drift) => {
    const result = await invoke(entrypoint, fixtureBytes(fixture), fixture.request.headers, {
      provider: 'workos', secrets: fixture.options.secrets, now: () => timestamp + drift,
    });

    expect(result.ok).toBe(Math.abs(drift) === 180);

    if (!result.ok) expect(result.reason).toBe(drift < 0 ? 'timestamp-future' : 'timestamp-expired');
  });

  test.each([-0.001, 0, 0.001])('explicit zero stays zero-width at drift %f', async (drift) => {
    const result = await invoke(entrypoint, fixtureBytes(fixture), fixture.request.headers, {
      provider: 'workos', secrets: fixture.options.secrets, toleranceSeconds: 0, now: () => timestamp + drift,
    });

    expect(result.ok).toBe(drift === 0);

    if (!result.ok) expect(result.reason).toBe(drift < 0 ? 'timestamp-future' : 'timestamp-expired');
  });

  test('explicit override expands tolerance without changing units', async () => {
    const result = await invoke(entrypoint, fixtureBytes(fixture), fixture.request.headers, {
      provider: 'workos', secrets: fixture.options.secrets, toleranceSeconds: 300, now: () => timestamp + 300,
    });

    expect(result.ok).toBe(true);
  });

  test('native default clock retains millisecond precision at zero tolerance', async () => {
    const body = new Uint8Array([255, 0, 195, 40]);
    const timestampMs = 1700000100123;
    const secret = 'phase4_native_clock_synthetic';
    const signature = createHmac('sha256', secret).update(Buffer.concat([Buffer.from(`${timestampMs}.`), body])).digest('hex');
    const clock = jest.spyOn(Date, 'now').mockReturnValue(timestampMs);

    try {
      const result = await invoke(entrypoint, body, { 'workos-signature': `t=${timestampMs},v1=${signature}` }, {
        provider: 'workos', secrets: [secret], toleranceSeconds: 0,
      });

      expect(result.ok).toBe(true);

      if (result.ok) expect(result.identity.timestamp).toBe(timestampMs / 1000);
    } finally {
      clock.mockRestore();
    }
  });
});

test.each(['stripe', 'standard-webhooks', 'clerk', 'svix', 'paddle'] as const)('%s keeps its prior omitted tolerance', async (provider) => {
  const fixture = firstPositive(provider);
  const timestamp = fixture.expected.identity?.timestamp;

  if (timestamp === null || timestamp === undefined) throw new Error('Missing timestamp');

  const tolerance = provider === 'paddle' ? 5 : 300;

  for (const entrypoint of ENTRYPOINTS) {
    for (const drift of [-tolerance - 1, -tolerance, tolerance, tolerance + 1]) {
      const result = await invoke(entrypoint, fixtureBytes(fixture), fixture.request.headers, {
        provider, secrets: fixture.options.secrets, now: () => timestamp + drift,
      });

      expect(result.ok).toBe(Math.abs(drift) === tolerance);

      if (!result.ok) expect(result.reason).toBe(drift < 0 ? 'timestamp-future' : 'timestamp-expired');
    }
  }
});

const DETAILS = {
  'dodo-payments': { headers: ['webhook-id', 'webhook-timestamp', 'webhook-signature'], grammar: 'v1,<base64-signature>', env: 'DODO_WEBHOOK_SECRET' },
  gitlab: { headers: ['webhook-id', 'webhook-timestamp', 'webhook-signature'], grammar: 'no X-Gitlab-Token fallback', env: 'GITLAB_WEBHOOK_SECRET' },
  replicate: { headers: ['webhook-id', 'webhook-timestamp', 'webhook-signature'], grammar: 'v1,<base64-signature>', env: 'REPLICATE_WEBHOOK_SECRET' },
  workos: { headers: ['WorkOS-Signature'], grammar: 't=<unix-milliseconds>', env: 'WORKOS_WEBHOOK_SECRET' },
} as const;

test.each(PROVIDERS)('%s diagnostics redact inputs and CLI selects the actual default env', async (provider) => {
  const fixture = firstPositive(provider);
  const failure = await verify({ rawBody: fixtureBytes(fixture), headers: {} }, fixtureOptions(provider, fixture));

  if (failure.ok) throw new Error('Missing signature must fail');

  const clean = diagnose(failure, { verbose: true });
  const details = DETAILS[provider];
  expect(clean.code).toBe('missing-signature');
  expect(clean.provider).toBe(provider);
  expect(clean.detail?.expectedHeaders).toEqual(details.headers);
  expect(clean.detail?.grammar).toContain(details.grammar);
  const canary = 'PHASE4_PRIVATE_DIAGNOSTIC_CANARY_772331';
  const polluted = { ...failure, message: canary, cause: canary, rawBody: canary, signature: canary, secret: canary, id: canary };
  expect(diagnose(polluted, { verbose: true })).toEqual(clean);
  expect(JSON.stringify(diagnose(polluted, { verbose: true }))).not.toContain(canary);
  const parsed = parseArgs(['init', 'webhook', '--provider', provider, '--framework', 'express']);

  if (parsed.kind !== 'command') throw new Error('Provider must parse');

  expect(parsed.command.provider).toBe(provider);
  expect(parsed.command.secretEnv).toBe(details.env);
});

const ADAPTERS = ['express', 'hono', 'nextjs', 'cloudflare'] as const;

type Adapter = (typeof ADAPTERS)[number];

interface AdapterOutcome {
  readonly status: number;
  readonly body: string;
  readonly calls: number;
}

function binaryInput(provider: (typeof PROVIDERS)[number]) {
  const body = new Uint8Array([255, 0, 195, 40, 13, 10]);
  const timestamp = 1700000100.123;
  const id = 'phase4_synthetic_signed_message';
  const secret = provider === 'workos' ? 'PHASE4_PRIVATE_ADAPTER_SECRET_441239' : `whsec_${Buffer.alloc(32, 17).toString('base64')}`;
  const prefix = provider === 'workos' ? `${timestamp * 1000}.` : `${id}.1700000100.`;
  const key = provider === 'workos' ? Buffer.from(secret) : Buffer.from(secret.slice(6), 'base64');
  const digest = createHmac('sha256', key).update(Buffer.concat([Buffer.from(prefix), body]));

  const headers = provider === 'workos'
    ? new Headers({ 'workos-signature': `t=${timestamp * 1000},v1=${digest.digest('hex')}` })
    : new Headers({ 'webhook-id': id, 'webhook-timestamp': '1700000100', 'webhook-signature': `v1,${digest.digest('base64')}` });

  return { body, headers, secret, timestamp: provider === 'workos' ? timestamp : 1700000100, id };
}

describe.each(PROVIDERS)('%s real adapters', (provider) => {
  test.each(ADAPTERS)('%s authenticates exact binary and rejects tampering without handler or leaks', async (adapter) => {
    const input = binaryInput(provider);
    const options: VerifyOptions = { provider, secrets: [input.secret], now: () => input.timestamp };
    const accepted = await exerciseAdapter(adapter, input.body, input.headers, options);
    expect(accepted).toEqual({ status: 200, body: Buffer.from(input.body).toString('hex'), calls: 1 });
    const changed = new Uint8Array(input.body);
    changed[0] = 254;
    const rejected = await exerciseAdapter(adapter, changed, input.headers, options);
    expect(rejected).toEqual({ status: 400, body: 'Bad Request', calls: 0 });

    for (const canary of [input.secret, input.id, Buffer.from(input.body).toString('hex'), ...input.headers.values()]) {
      expect(rejected.body).not.toContain(canary);
    }
  });
});

test.each(ADAPTERS)('%s propagates WorkOS omitted freshness default', async (adapter) => {
  const input = binaryInput('workos');

  const result = await exerciseAdapter(adapter, input.body, input.headers, {
    provider: 'workos', secrets: [input.secret], now: () => input.timestamp + 180.001,
  });

  expect(result).toEqual({ status: 400, body: 'Bad Request', calls: 0 });
});

async function exerciseAdapter(adapter: Adapter, body: Uint8Array, headers: Headers, options: VerifyOptions): Promise<AdapterOutcome> {
  let calls = 0;

  const request = () => new Request('https://hooklatch.test/webhook', {
    method: 'POST', headers, body: new Uint8Array(body),
  });

  if (adapter === 'express') {
    const app = express();
    app.use(createExpressMiddleware(options));
    app.post('/', (req, res) => {
      calls += 1;

      if (!req.webhook) throw new Error('Missing verified request');

      res.send(Buffer.from(req.webhook.rawBody).toString('hex'));
    });
    const server = createServer(app);

    try {
      server.listen(0, '127.0.0.1');
      await once(server, 'listening');
      const address = server.address();

      if (!isTcpAddress(address)) throw new Error('Expected local TCP address');

      const response = await fetch(`http://127.0.0.1:${address.port}/`, {
        method: 'POST', headers, body: new Uint8Array(body), signal: AbortSignal.timeout(5000),
      });

      return { status: response.status, body: await response.text(), calls };
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) => server.close((error) => {
        if (error) reject(error);
        else resolve();
      }));
    }
  }

  let response: Response;

  if (adapter === 'hono') {
    const app = new Hono();
    app.use('*', createHonoMiddleware(options));
    app.post('/webhook', (context) => {
      calls += 1;
      const success = context.get('webhook');

      if (!success) throw new Error('Missing verified request');

      return context.text(Buffer.from(success.rawBody).toString('hex'));
    });
    response = await app.request(request());
  } else if (adapter === 'nextjs') {
    const handler = createNextHandler({
      ...options,
      handler: (_request, success) => {
        calls += 1;

        return new Response(Buffer.from(success.rawBody).toString('hex'));
      },
    });

    response = await handler(request());
  } else {
    const handler = createWorkerHandler({
      options: () => options,
      handler: (_request, _env, _context, success) => {
        calls += 1;

        return new Response(Buffer.from(success.rawBody).toString('hex'));
      },
    });

    response = await handler(request(), {}, {});
  }

  return { status: response.status, body: await response.text(), calls };
}


