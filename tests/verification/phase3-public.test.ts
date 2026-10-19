import { createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { once } from 'node:events';
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
import { combinedHeader, fixtureBytes, fixtureOptions, isUnsignedOrNull, loadFixture, representationsOf } from './helpers.js';

// Fixture JSON is untrusted at the read boundary; validate its schema before use.
interface Phase3FixtureFile {
  readonly cases: readonly FixtureCase[];
}

function isString(value: unknown): value is string {
  return typeof value === 'string';
}

function isIdentityValue(value: unknown): value is string | number | null {
  return value === null || typeof value === 'string' || typeof value === 'number';
}

function isHeaderValue(value: unknown): value is string | readonly string[] {
  return isString(value) || (Array.isArray(value) && value.every(isString));
}

/** Mirrors the shared loader's schema guard; the shared loader is legacy-files-only and must stay unchanged. */
function isFixtureFile(value: unknown): value is Phase3FixtureFile {
  if (typeof value !== 'object' || value === null || !('cases' in value) || !Array.isArray(value.cases)) return false;

  return value.cases.every((entry: unknown): entry is FixtureCase => {
    if (typeof entry !== 'object' || entry === null) return false;

    if (!('id' in entry) || typeof entry.id !== 'string') return false;

    if (!('request' in entry) || typeof entry.request !== 'object' || entry.request === null) return false;

    if (!('bodyBase64' in entry.request) || typeof entry.request.bodyBase64 !== 'string') return false;

    if (!('headers' in entry.request) || typeof entry.request.headers !== 'object' || entry.request.headers === null) return false;

    if (!Object.values(entry.request.headers).every(isHeaderValue)) return false;

    if (!('options' in entry) || typeof entry.options !== 'object' || entry.options === null) return false;

    if (!('secrets' in entry.options) || !Array.isArray(entry.options.secrets) || !entry.options.secrets.every(isString)) return false;

    if (!('now' in entry.options) || typeof entry.options.now !== 'number') return false;

    if ('maxBodyBytes' in entry.options && typeof entry.options.maxBodyBytes !== 'number') return false;

    if ('toleranceSeconds' in entry.options && typeof entry.options.toleranceSeconds !== 'number') return false;

    if (!('expected' in entry) || typeof entry.expected !== 'object' || entry.expected === null) return false;

    if (!('ok' in entry.expected) || typeof entry.expected.ok !== 'boolean') return false;

    if ('reason' in entry.expected && typeof entry.expected.reason !== 'string') return false;

    if ('identity' in entry.expected) {
      const identity = entry.expected.identity;

      if (typeof identity !== 'object' || identity === null) return false;

      if (!('deliveryId' in identity) || !isIdentityValue(identity.deliveryId)) return false;

      if (!('eventId' in identity) || !isIdentityValue(identity.eventId)) return false;

      if (!('timestamp' in identity) || (identity.timestamp !== null && typeof identity.timestamp !== 'number')) return false;

      if (!('authenticatedFields' in identity) || !Array.isArray(identity.authenticatedFields) || !identity.authenticatedFields.every(isString)) return false;
    }

    if (!('provenance' in entry) || typeof entry.provenance !== 'object' || entry.provenance === null) return false;

    if (!('class' in entry.provenance) || (entry.provenance.class !== 'reference' && entry.provenance.class !== 'local')) return false;

    if ('commit' in entry.provenance && typeof entry.provenance.commit !== 'string') return false;

    if ('fetched' in entry.provenance && typeof entry.provenance.fetched !== 'string') return false;

    if ('notes' in entry && typeof entry.notes !== 'string') return false;

    return 'source' in entry.provenance && typeof entry.provenance.source === 'string';
  });
}

function loadPhase3FixtureFile(fileName: string): readonly FixtureCase[] {
  const raw = readFileSync(new URL(`../fixtures/${fileName}`, import.meta.url), 'utf8');
  const parsed: unknown = JSON.parse(raw);

  if (!isFixtureFile(parsed)) throw new Error(`Phase 3 fixture file ${fileName} is malformed`);

  return parsed.cases;
}


const PROVIDERS = ['razorpay', 'paddle', 'lemon-squeezy'] as const;
const ENTRYPOINTS = ['verify', 'verifyRequest', 'createVerifier'] as const;

type EntryPoint = (typeof ENTRYPOINTS)[number];

function casesFor(provider: string): readonly FixtureCase[] {
  return loadPhase3FixtureFile(`${provider}.json`);
}

function firstPositive(provider: string): FixtureCase {
  const fixture = casesFor(provider).find((item) => item.expected.ok);

  if (fixture === undefined) throw new Error('Missing positive fixture');

  return fixture;
}

function isHeaderList(value: string | readonly string[]): value is readonly string[] {
  return Array.isArray(value);
}

function webHeaders(headers: HeaderInput): Headers {
  if (headers instanceof Headers) return new Headers(headers);

  const result = new Headers();

  if (Array.isArray(headers)) {
    for (const [key, value] of headers) result.append(key, value);
  } else {
    for (const [key, value] of Object.entries(headers)) {
      if (value === undefined) continue;

      if (isHeaderList(value)) {
        for (const item of value) result.append(key, item);
      } else result.append(key, value);
    }
  }

  return result;
}

async function invoke(entrypoint: EntryPoint, rawBody: Uint8Array, headers: HeaderInput, options: VerifyOptions): Promise<VerificationResult> {
  if (entrypoint === 'verify') return verify({ rawBody, headers }, options);

  if (entrypoint === 'createVerifier') return createVerifier(options)({ rawBody, headers });

  return verifyRequest(new Request('https://hooklatch.test/webhook', {
    method: 'POST', headers: webHeaders(headers), body: new Uint8Array(rawBody),
  }), options);
}

function expectedEventId(fixture: FixtureCase, headerIsWeb: boolean): string | number | null | undefined {
  const identity = fixture.expected.identity;

  if (identity === undefined || !isUnsignedOrNull(identity.eventId)) return identity?.eventId;

  const value = combinedHeader(fixture, 'x-razorpay-event-id');

  if (value === undefined || value.trim() === '') return null;

  // WHATWG Headers trims outer whitespace; record and tuple input preserve it.
  return headerIsWeb ? value.trim() : value;
}

describe.each(PROVIDERS)('%s public fixture qualification', (provider) => {
  const fixtures = casesFor(provider);

  test('fixture cardinality and exact expectations are pinned', () => {
    expect(fixtures).toHaveLength({ razorpay: 20, paddle: 33, 'lemon-squeezy': 15 }[provider]);
    expect(new Set(fixtures.map((fixture) => fixture.id)).size).toBe(fixtures.length);

    for (const fixture of fixtures) {
      if (fixture.expected.ok) expect(fixture.expected.identity).toBeDefined();
      else expect(fixture.expected.reason).toBeDefined();
    }
  });

  describe.each(ENTRYPOINTS)('%s', (entrypoint) => {
    test.each(fixtures)('$id authenticates exact bytes or returns the exact failure', async (fixture) => {
      const bytes = fixtureBytes(fixture);

      for (const [index, headers] of representationsOf(fixture).entries()) {
        const result = await invoke(entrypoint, bytes, headers, fixtureOptions(provider, fixture));
        expect(result.ok).toBe(fixture.expected.ok);
        expect(result.provider).toBe(provider);

        if (result.ok) {
          expect(result.rawBody).toEqual(bytes);
          expect(result.identity).toEqual({
            ...fixture.expected.identity,
            eventId: expectedEventId(fixture, entrypoint === 'verifyRequest' || index === 2),
          });
        } else expect(result.reason).toBe(fixture.expected.reason);
      }
    });
  });
});

describe.each(ENTRYPOINTS)('%s Paddle tolerance policy', (entrypoint) => {
  const fixture = firstPositive('paddle');
  const timestamp = fixture.expected.identity?.timestamp;

  if (timestamp === null || timestamp === undefined) throw new Error('Paddle fixture requires timestamp');

  test.each([
    [-5, true, undefined], [5, true, undefined], [-6, false, 'timestamp-future'], [6, false, 'timestamp-expired'],
  ] as const)('omitted tolerance at drift %i', async (drift, ok, reason) => {
    const result = await invoke(entrypoint, fixtureBytes(fixture), fixture.request.headers, {
      provider: 'paddle', secrets: fixture.options.secrets, now: () => timestamp + drift,
    });

    expect(result.ok).toBe(ok);

    if (!result.ok) expect(result.reason).toBe(reason);
  });

  test.each([-1, 0, 1])('explicit zero at drift %i', async (drift) => {
    const result = await invoke(entrypoint, fixtureBytes(fixture), fixture.request.headers, {
      provider: 'paddle', secrets: fixture.options.secrets, toleranceSeconds: 0, now: () => timestamp + drift,
    });

    expect(result.ok).toBe(drift === 0);

    if (!result.ok) expect(result.reason).toBe(drift < 0 ? 'timestamp-future' : 'timestamp-expired');
  });

  test.each([-300, 300])('explicit override expands tolerance at drift %i', async (drift) => {
    const result = await invoke(entrypoint, fixtureBytes(fixture), fixture.request.headers, {
      provider: 'paddle', secrets: fixture.options.secrets, toleranceSeconds: 300, now: () => timestamp + drift,
    });

    expect(result.ok).toBe(true);
  });
});

const LEGACY_TIMESTAMPED = ['stripe', 'standard-webhooks', 'clerk', 'svix'] as const;

describe.each(LEGACY_TIMESTAMPED)('%s preserves omitted 300-second default', (provider) => {
  const fixtures = provider === 'clerk' || provider === 'svix' ? casesFor(provider) : loadFixture(provider);
  const fixture = fixtures.find((item) => item.expected.ok && item.expected.identity?.timestamp !== null);

  if (fixture === undefined || fixture.expected.identity?.timestamp === undefined || fixture.expected.identity.timestamp === null) throw new Error('Missing timestamped fixture');

  const timestamp = fixture.expected.identity.timestamp;

  test.each(ENTRYPOINTS)('%s keeps both inclusive boundaries and rejects one second beyond', async (entrypoint) => {
    for (const drift of [-301, -300, 300, 301]) {
      const result = await invoke(entrypoint, fixtureBytes(fixture), fixture.request.headers, {
        provider, secrets: fixture.options.secrets, now: () => timestamp + drift,
      });

      expect(result.ok).toBe(Math.abs(drift) === 300);

      if (!result.ok) expect(result.reason).toBe(drift < 0 ? 'timestamp-future' : 'timestamp-expired');
    }
  });
});

const DIAGNOSTIC_DETAILS = {
  razorpay: { header: 'X-Razorpay-Signature', grammar: 'hexadecimal', env: 'RAZORPAY_WEBHOOK_SECRET' },
  paddle: { header: 'Paddle-Signature', grammar: 'ts=<unix-seconds>;h1=', env: 'PADDLE_WEBHOOK_SECRET' },
  'lemon-squeezy': { header: 'X-Signature', grammar: 'hexadecimal', env: 'LEMON_SQUEEZY_WEBHOOK_SECRET' },
} as const;

test.each(PROVIDERS)('%s diagnostics stay static and CLI uses its own environment name', async (provider) => {
  const fixture = firstPositive(provider);
  const failure = await verify({ rawBody: fixtureBytes(fixture), headers: {} }, fixtureOptions(provider, fixture));
  expect(failure.ok).toBe(false);

  if (failure.ok) throw new Error('Missing signature must fail');

  const details = DIAGNOSTIC_DETAILS[provider];
  const clean = diagnose(failure, { verbose: true });
  expect(clean.code).toBe('missing-signature');
  expect(clean.provider).toBe(provider);
  expect(clean.detail?.expectedHeaders).toEqual([details.header]);
  expect(clean.detail?.grammar).toContain(details.grammar);
  const canary = 'PRIVATE_CANARY_PHASE3_74aef991';
  const polluted = { ...failure, message: canary, cause: { secret: canary }, rawBody: canary, signature: canary, id: canary };
  expect(diagnose(polluted, { verbose: true })).toEqual(clean);
  expect(JSON.stringify(diagnose(polluted, { verbose: true }))).not.toContain(canary);
  const parsed = parseArgs(['init', 'webhook', '--provider', provider, '--framework', 'express']);
  expect(parsed.kind).toBe('command');

  if (parsed.kind !== 'command') throw new Error('Registered provider must parse');

  expect(parsed.command.provider).toBe(provider);
  expect(parsed.command.secretEnv).toBe(details.env);
});

// Body-only protocols ignore the clock for authentication; unsigned metadata never
// acquires authenticatedFields, including a forged-but-valid event-id replacement.
test.each(['razorpay', 'lemon-squeezy'] as const)('%s has no timestamp replay claim', async (provider) => {
  const fixture = firstPositive(provider);

  for (const entrypoint of ENTRYPOINTS) {
    const result = await invoke(entrypoint, fixtureBytes(fixture), fixture.request.headers, {
      provider, secrets: fixture.options.secrets, toleranceSeconds: 0, now: () => 0,
    });

    expect(result.ok).toBe(true);

    if (result.ok) {
      expect(result.identity.timestamp).toBeNull();
      expect(result.identity.authenticatedFields).toEqual([]);
    }
  }
});

// Independent signing verifies the API recipe rather than reusing descriptor helpers.
test.each(PROVIDERS)('%s freshly signed non-JSON bytes pass all public entrypoints', async (provider) => {
  const rawBody = new Uint8Array([0xff, 0, 0xc3, 0x28, 7]);
  const timestamp = 1700000000;
  const secret = 'phase3_public_synthetic_secret';
  const signed = provider === 'paddle' ? Buffer.concat([Buffer.from(`${timestamp}:`), rawBody]) : rawBody;
  const signature = createHmac('sha256', secret).update(signed).digest('hex');

  const headers = provider === 'paddle' ? { 'Paddle-Signature': `ts=${timestamp};h1=${signature}` }
    : provider === 'razorpay' ? { 'X-Razorpay-Signature': signature } : { 'X-Signature': signature };

  for (const entrypoint of ENTRYPOINTS) {
    const result = await invoke(entrypoint, rawBody, headers, { provider, secrets: [secret], now: () => timestamp });
    expect(result.ok).toBe(true);

    if (result.ok) expect(result.rawBody).toEqual(rawBody);
  }
});

const ADAPTERS = ['express', 'hono', 'nextjs', 'cloudflare'] as const;

type Adapter = (typeof ADAPTERS)[number];

interface AdapterOutcome {
  readonly status: number;
  readonly body: string;
  readonly calls: number;
}

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

describe.each(PROVIDERS)('%s real adapter public integration', (provider) => {
  test.each(ADAPTERS)('%s accepts exact binary bytes and rejects a same-size tamper', async (adapter) => {
    const rawBody = new Uint8Array([0xff, 0, 0xc3, 0x28, 7]);
    const timestamp = 1700000000;
    const secret = 'phase3_adapter_synthetic_secret';
    const signed = provider === 'paddle' ? Buffer.concat([Buffer.from(`${timestamp}:`), rawBody]) : rawBody;
    const signature = createHmac('sha256', secret).update(signed).digest('hex');
    const headers = new Headers();
    headers.set(provider === 'paddle' ? 'Paddle-Signature' : provider === 'razorpay' ? 'X-Razorpay-Signature' : 'X-Signature',
      provider === 'paddle' ? `ts=${timestamp};h1=${signature}` : signature);
    const options: VerifyOptions = { provider, secrets: [secret], now: () => timestamp + (provider === 'paddle' ? 5 : 0) };
    const accepted = await exerciseAdapter(adapter, rawBody, headers, options);
    expect(accepted).toEqual({ status: 200, body: Buffer.from(rawBody).toString('hex'), calls: 1 });
    const tampered = new Uint8Array([0xff, 0, 0xc3, 0x28, 8]);
    const rejected = await exerciseAdapter(adapter, tampered, headers, options);
    expect(rejected).toEqual({ status: 400, body: 'Bad Request', calls: 0 });
  });
});

test.each(ADAPTERS)('%s passes Paddle default freshness to core unchanged', async (adapter) => {
  const fixture = firstPositive('paddle');
  const timestamp = fixture.expected.identity?.timestamp;

  if (timestamp === null || timestamp === undefined) throw new Error('Missing timestamp');

  const result = await exerciseAdapter(adapter, fixtureBytes(fixture), webHeaders(fixture.request.headers), {
    provider: 'paddle', secrets: fixture.options.secrets, now: () => timestamp + 6,
  });

  expect(result).toEqual({ status: 400, body: 'Bad Request', calls: 0 });
});
