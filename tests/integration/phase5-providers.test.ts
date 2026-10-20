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
import type { FixtureCase } from '../verification/helpers.js';
import { fixtureBytes, fixtureOptions, isFixtureFile, representationsOf } from '../verification/helpers.js';

const PROVIDERS = ['sentry', 'doppler', 'sanity'] as const;
const ENTRYPOINTS = ['verify', 'createVerifier', 'verifyRequest'] as const;

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

function toWebHeaders(fixture: FixtureCase): Headers {
  const headers = representationsOf(fixture)[2];

  if (!(headers instanceof Headers)) throw new Error('Missing Web Headers representation');

  return headers;
}

async function invoke(entrypoint: EntryPoint, fixture: FixtureCase, headers: HeaderInput, options: VerifyOptions): Promise<VerificationResult> {
  const rawBody = fixtureBytes(fixture);

  if (entrypoint === 'verify') return verify({ rawBody, headers }, options);

  if (entrypoint === 'createVerifier') return createVerifier(options)({ rawBody, headers });

  return verifyRequest(new Request('https://hooklatch.test/webhook', {
    method: 'POST', headers: toWebHeaders(fixture), body: new Uint8Array(rawBody),
  }), options);
}

function assertResult(result: VerificationResult, fixture: FixtureCase, expected: FixtureCase['expected']): void {
  expect(result.ok).toBe(expected.ok);

  if (result.ok) {
    expect(expected.identity).toBeDefined();
    expect(result.identity).toEqual(expected.identity);
    expect(result.rawBody).toEqual(fixtureBytes(fixture));
  } else expect(result.reason).toBe(expected.reason);
}

describe.each(PROVIDERS)('%s Phase 5 public qualification', (provider) => {
  const fixtures = casesFor(provider);

  test('pins corpus cardinality and unique IDs', () => {
    expect(fixtures).toHaveLength({ sentry: 24, doppler: 24, sanity: 58 }[provider]);
    expect(new Set(fixtures.map((fixture) => fixture.id)).size).toBe(fixtures.length);
  });

  test.each(fixtures)('$id agrees across public entrypoints and transport-specific header normalization', async (fixture) => {
    for (const entrypoint of ENTRYPOINTS) {
      const representations = entrypoint === 'verifyRequest' ? [toWebHeaders(fixture)] : representationsOf(fixture);

      for (const headers of representations) {
        const expected = headers instanceof Headers ? fixture.webHeadersExpected ?? fixture.expected : fixture.expected;
        const result = await invoke(entrypoint, fixture, headers, fixtureOptions(provider, fixture));
        expect(result.provider).toBe(provider);
        assertResult(result, fixture, expected);
      }
    }
  });
});

const DETAILS = {
  sentry: { header: 'Sentry-Hook-Signature', env: 'SENTRY_WEBHOOK_SECRET' },
  doppler: { header: 'X-Doppler-Signature', env: 'DOPPLER_WEBHOOK_SECRET' },
  sanity: { header: 'sanity-webhook-signature', env: 'SANITY_WEBHOOK_SECRET' },
} as const;

test.each(PROVIDERS)('%s diagnostics redact all input and CLI selects actual default env', async (provider) => {
  const fixture = firstPositive(provider);
  const failure = await verify({ rawBody: fixtureBytes(fixture), headers: {} }, fixtureOptions(provider, fixture));

  if (failure.ok) throw new Error('Missing signature must fail');

  const clean = diagnose(failure, { verbose: true });
  expect(clean.code).toBe('missing-signature');
  expect(clean.provider).toBe(provider);
  expect(clean.detail?.expectedHeaders).toEqual([DETAILS[provider].header]);
  const canary = 'PHASE5_DIAGNOSTICS_PRIVATE_CANARY_718329';
  const polluted = { ...failure, message: canary, cause: canary, rawBody: canary, signature: canary, secret: canary, id: canary };
  expect(diagnose(polluted, { verbose: true })).toEqual(clean);
  expect(JSON.stringify(clean)).not.toContain(canary);
  const parsed = parseArgs(['init', 'webhook', '--provider', provider, '--framework', 'express']);

  if (parsed.kind !== 'command') throw new Error('Provider must parse');

  expect(parsed.command.provider).toBe(provider);
  expect(parsed.command.secretEnv).toBe(DETAILS[provider].env);
});

describe.each(ENTRYPOINTS)('%s Sanity freshness', (entrypoint) => {
  const fixture = firstPositive('sanity');
  const timestamp = fixture.expected.identity?.timestamp;

  if (timestamp === null || timestamp === undefined) throw new Error('Missing Sanity timestamp');

  test.each([-300.001, -300, 300, 300.001])('omitted 300-second tolerance at drift %f', async (drift) => {
    const result = await invoke(entrypoint, fixture, fixture.request.headers, {
      provider: 'sanity', secrets: fixture.options.secrets, now: () => timestamp + drift,
    });

    expect(result.ok).toBe(Math.abs(drift) === 300);

    if (!result.ok) expect(result.reason).toBe(drift < 0 ? 'timestamp-future' : 'timestamp-expired');
  });

  test.each([-0.001, 0, 0.001])('explicit zero is zero-width at drift %f', async (drift) => {
    const result = await invoke(entrypoint, fixture, fixture.request.headers, {
      provider: 'sanity', secrets: fixture.options.secrets, toleranceSeconds: 0, now: () => timestamp + drift,
    });

    expect(result.ok).toBe(drift === 0);

    if (!result.ok) expect(result.reason).toBe(drift < 0 ? 'timestamp-future' : 'timestamp-expired');
  });

  test('explicit override expands tolerance and bad MAC still precedes freshness', async () => {
    const options: VerifyOptions = { provider: 'sanity', secrets: fixture.options.secrets, toleranceSeconds: 600, now: () => timestamp + 600 };
    expect((await invoke(entrypoint, fixture, fixture.request.headers, options)).ok).toBe(true);
    const bad = { ...fixture, request: { ...fixture.request, bodyBase64: Buffer.from('phase5_tampered').toString('base64') } };
    const result = await invoke(entrypoint, bad, bad.request.headers, { ...options, now: () => timestamp + 601 });
    expect(result.ok).toBe(false);

    if (!result.ok) expect(result.reason).toBe('invalid-signature');
  });

  test('default native clock preserves milliseconds', async () => {
    const input = signedInput('sanity');
    const clock = jest.spyOn(Date, 'now').mockReturnValue(input.timestamp * 1000);

    try {
      const result = await invoke(entrypoint, input.fixture, input.fixture.request.headers, {
        provider: 'sanity', secrets: [input.secret], toleranceSeconds: 0,
      });

      expect(result.ok).toBe(true);

      if (result.ok) expect(result.identity.timestamp).toBe(input.timestamp);
    } finally {
      clock.mockRestore();
    }
  });
});

test('Sanity captures fractional ingress clock before the Request body is pulled', async () => {
  const input = signedInput('sanity');
  const clock = jest.spyOn(Date, 'now').mockReturnValue(input.timestamp * 1000);
  let pulls = 0;

  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      pulls += 1;
      clock.mockReturnValue((input.timestamp + 1000) * 1000);
      controller.enqueue(input.body);
      controller.close();
    },
  }, { highWaterMark: 0 });

  const init: RequestInit & { duplex: 'half' } = { method: 'POST', headers: input.headers, body: stream, duplex: 'half' };

  try {
    expect(pulls).toBe(0);

    const result = await verifyRequest(new Request('https://hooklatch.test/webhook', init), {
      provider: 'sanity', secrets: [input.secret], toleranceSeconds: 0,
    });

    expect(pulls).toBe(1);
    expect(result.ok).toBe(true);

    if (result.ok) expect(result.identity.timestamp).toBe(input.timestamp);
  } finally {
    clock.mockRestore();
  }
});

test.each(['sentry', 'doppler'] as const)('%s ignores unsigned timestamps instead of claiming freshness', async (provider) => {
  const fixture = firstPositive(provider);

  const changed = { ...fixture, request: { ...fixture.request, headers: {
    ...fixture.request.headers, 'sentry-hook-timestamp': '1', 'x-doppler-timestamp': '9999999999999', 'request-id': 'unsigned-id',
  } } };

  for (const entrypoint of ENTRYPOINTS) {
    const result = await invoke(entrypoint, changed, changed.request.headers, {
      provider, secrets: fixture.options.secrets, now: () => 999999999999, toleranceSeconds: 0,
    });

    assertResult(result, changed, fixture.expected);
  }
});

const ADAPTERS = ['express', 'hono', 'nextjs', 'cloudflare'] as const;

type Adapter = (typeof ADAPTERS)[number];

interface AdapterOutcome { readonly status: number; readonly body: string; readonly calls: number }

function signedInput(provider: (typeof PROVIDERS)[number]) {
  const body = new Uint8Array([255, 0, 195, 40, 13, 10]);
  const timestampMs = 1700000100123;
  const secret = 'PHASE5_ADAPTER_SYNTHETIC_SECRET_781369';
  const digest = createHmac('sha256', secret);

  if (provider === 'sanity') digest.update(`${timestampMs}.`);

  digest.update(body);
  const signature = provider === 'sanity' ? digest.digest('base64url') : digest.digest('hex');
  const header = provider === 'sanity' ? `t=${timestampMs},v1=${signature}` : provider === 'doppler' ? `sha256=${signature}` : signature;
  const headers = new Headers({ [DETAILS[provider].header]: header });

  const fixture: FixtureCase = {
    id: 'independent-binary-adapter', provenance: { class: 'local', source: 'Independent node:crypto synthetic protocol input' },
    request: { bodyBase64: Buffer.from(body).toString('base64'), headers: Object.fromEntries(headers) },
    options: { secrets: [secret], now: timestampMs / 1000 }, expected: { ok: true },
  };

  return { body, headers, secret, fixture, timestamp: timestampMs / 1000 };
}

describe.each(PROVIDERS)('%s real adapters', (provider) => {
  test.each(ADAPTERS)('%s accepts independent bytes and rejects tampering before handler', async (adapter) => {
    const input = signedInput(provider);
    const options: VerifyOptions = { provider, secrets: [input.secret], now: () => input.timestamp };
    expect(await exerciseAdapter(adapter, input.body, input.headers, options)).toEqual({
      status: 200, body: Buffer.from(input.body).toString('hex'), calls: 1,
    });
    const tampered = new Uint8Array(input.body);
    tampered[0] = 254;
    const rejected = await exerciseAdapter(adapter, tampered, input.headers, options);
    expect(rejected).toEqual({ status: 400, body: 'Bad Request', calls: 0 });

    for (const canary of [input.secret, ...input.headers.values()]) expect(rejected.body).not.toContain(canary);
  });
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



