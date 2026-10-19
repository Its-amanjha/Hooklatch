import { readFileSync } from 'node:fs';
import { diagnose } from '../../src/diagnostics/index.js';
import type { Diagnostic } from '../../src/diagnostics/index.js';
import { verify } from '../../src/index.js';
import { HooklatchError } from '../../src/errors.js';
import { SUPPORTED_PROVIDERS } from '../../src/providers/index.js';
import type {
  HooklatchErrorCode,
  Provider,
  VerificationFailure,
  VerificationFailureReason,
  VerificationSuccess,
} from '../../src/types.js';
import { fixtureBytes, fixtureOptions, loadFixture, type FixtureCase } from '../verification/helpers.js';

/**
 * Phase 2 integration qualification for the diagnostics surface.
 *
 * Every check here is driven by the real pure `diagnose` helper and real
 * verification results over all six fixture files (52 legacy + 40 preset
 * cases). Signed fixture bytes are never modified; canaries are added to the
 * failure objects handed to `diagnose`, never to the signed inputs.
 */

interface CorpusEntry {
  readonly provider: BaselineProvider;
  readonly case_: FixtureCase;
}

const PINNED_PROVIDER_ORDER = [
  'stripe',
  'github',
  'shopify',
  'standard-webhooks',
  'clerk',
  'svix',
] as const satisfies readonly Provider[];

type BaselineProvider = typeof PINNED_PROVIDER_ORDER[number];

/** The deep validation of the preset files lives in tests/verification/phase2-presets.test.ts. */
const PRESET_FIXTURE_FILES: Partial<Record<Provider, string>> = {
  clerk: '../fixtures/clerk.json',
  svix: '../fixtures/svix.json',
};

/** Pinned per-provider verbose expectations, corroborated against provider docs. */
interface ProviderDetailExpectation {
  readonly expectedHeaders: readonly string[];
  readonly grammarIncludes: readonly string[];
}

const PROVIDER_DETAIL_EXPECTATIONS: Readonly<Record<BaselineProvider, ProviderDetailExpectation>> = {
  stripe: {
    expectedHeaders: ['Stripe-Signature'],
    grammarIncludes: ['t=', 'v1='],
  },
  github: {
    expectedHeaders: ['X-Hub-Signature-256'],
    grammarIncludes: ['sha256='],
  },
  shopify: {
    expectedHeaders: ['X-Shopify-Hmac-Sha256'],
    grammarIncludes: ['Base64'],
  },
  'standard-webhooks': {
    expectedHeaders: ['webhook-id', 'webhook-timestamp', 'webhook-signature'],
    grammarIncludes: ['v1,'],
  },
  clerk: {
    expectedHeaders: ['svix-id', 'svix-timestamp', 'svix-signature'],
    grammarIncludes: ['v1,'],
  },
  svix: {
    expectedHeaders: [
      'svix-id',
      'svix-timestamp',
      'svix-signature',
      'webhook-id',
      'webhook-timestamp',
      'webhook-signature',
    ],
    grammarIncludes: ['v1,'],
  },
};

/** Fixture inventory pins. Changing these counts is a deliberate, documented act. */
const PINNED_CASE_COUNTS = {
  legacy: 52,
  svix: 24,
  clerk: 16,
  total: 92,
} as const;

const VERIFICATION_REASONS: readonly VerificationFailureReason[] = [
  'missing-signature',
  'malformed-signature',
  'unsupported-scheme',
  'invalid-signature',
  'missing-identity',
  'missing-timestamp',
  'timestamp-expired',
  'timestamp-future',
  'body-too-large',
];

const SETUP_CODES: readonly HooklatchErrorCode[] = [
  'unknown-provider',
  'missing-secrets',
  'invalid-secret',
  'invalid-options',
  'invalid-input',
  'body-consumed',
  'body-read-failed',
  'crypto-unavailable',
  'internal',
];

/** Deterministic rotation for verbose setup diagnostics. */
const SETUP_PROVIDER_BY_CODE: Readonly<Record<HooklatchErrorCode, BaselineProvider>> = {
  'unknown-provider': 'stripe',
  'missing-secrets': 'github',
  'invalid-secret': 'shopify',
  'invalid-options': 'standard-webhooks',
  'invalid-input': 'clerk',
  'body-consumed': 'svix',
  'body-read-failed': 'stripe',
  'crypto-unavailable': 'github',
  internal: 'shopify',
};

/** Provider option that must be rejected as a mismatch for that failure provider. */
const MISMATCH_FOR: Readonly<Record<BaselineProvider, BaselineProvider>> = {
  stripe: 'github',
  github: 'shopify',
  shopify: 'standard-webhooks',
  'standard-webhooks': 'clerk',
  clerk: 'svix',
  svix: 'stripe',
};

function isString(value: unknown): value is string {
  return typeof value === 'string';
}

interface PresetFixtureFile {
  readonly cases: readonly FixtureCase[];
}

function isPresetFixtureCase(value: unknown): value is FixtureCase {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;

  if (!('id' in value) || !isString(value.id)) return false;

  if (!('provenance' in value) || typeof value.provenance !== 'object' || value.provenance === null
    || Array.isArray(value.provenance)) {
    return false;
  }

  if (!('source' in value.provenance) || !isString(value.provenance.source)) return false;

  if (!('request' in value) || typeof value.request !== 'object' || value.request === null
    || Array.isArray(value.request)) {
    return false;
  }

  if (!('bodyBase64' in value.request) || !isString(value.request.bodyBase64)) return false;

  if (!('headers' in value.request) || typeof value.request.headers !== 'object'
    || value.request.headers === null) {
    return false;
  }

  if (!Object.values(value.request.headers).every((header) => isString(header)
    || (Array.isArray(header) && header.every(isString)))) {
    return false;
  }

  if (!('options' in value) || typeof value.options !== 'object' || value.options === null
    || Array.isArray(value.options)) {
    return false;
  }

  if (!('now' in value.options) || typeof value.options.now !== 'number') return false;

  if (!('secrets' in value.options) || !Array.isArray(value.options.secrets) || !value.options.secrets.every(isString)) {
    return false;
  }

  if (!('expected' in value) || typeof value.expected !== 'object' || value.expected === null
    || Array.isArray(value.expected)) {
    return false;
  }

  if (!('ok' in value.expected) || typeof value.expected.ok !== 'boolean') return false;

  if ('reason' in value.expected && !isString(value.expected.reason)) return false;

  return true;
}

function isPresetFixtureFile(value: unknown): value is PresetFixtureFile {
  if (typeof value !== 'object' || value === null || !('cases' in value) || !Array.isArray(value.cases)) return false;

  return value.cases.every(isPresetFixtureCase);
}

function loadPresetFixture(provider: BaselineProvider): readonly FixtureCase[] {
  const fixtureFile = PRESET_FIXTURE_FILES[provider];

  if (fixtureFile === undefined) {
    throw new Error(`No preset fixture file is assigned to provider ${provider}`);
  }

  const raw = readFileSync(new URL(fixtureFile, import.meta.url), 'utf8');
  const parsed: unknown = JSON.parse(raw);

  if (!isPresetFixtureFile(parsed)) {
    throw new Error(`Preset fixture file for ${provider} is malformed`);
  }

  return parsed.cases;
}

function isPresetProvider(provider: BaselineProvider): provider is Extract<BaselineProvider, 'clerk' | 'svix'> {
  return PRESET_FIXTURE_FILES[provider] !== undefined;
}

function loaderFor(provider: BaselineProvider): readonly FixtureCase[] {
  if (isPresetProvider(provider)) return loadPresetFixture(provider);

  return loadFixture(provider);
}

const CORPUS: readonly CorpusEntry[] = PINNED_PROVIDER_ORDER.flatMap((provider) =>
  loaderFor(provider).map((case_) => ({ provider, case_ })));

const EXPECTED_FAILURES: readonly CorpusEntry[] = CORPUS.filter((entry) => entry.case_.expected.ok === false);

const EXPECTED_SUCCESSES: readonly CorpusEntry[] = CORPUS.filter((entry) => entry.case_.expected.ok === true);

function requestFor(entry: CorpusEntry) {
  return { rawBody: fixtureBytes(entry.case_), headers: entry.case_.request.headers };
}

async function verifiedFailure(entry: CorpusEntry): Promise<VerificationFailure> {
  const result = await verify(requestFor(entry), fixtureOptions(entry.provider, entry.case_));

  expect(`${entry.provider}/${entry.case_.id} ok=${String(result.ok)}`).toBe(
    `${entry.provider}/${entry.case_.id} ok=false`);

  expect(`${entry.provider}/${entry.case_.id} reason=${result.ok ? 'none' : result.reason}`).toBe(
    `${entry.provider}/${entry.case_.id} reason=${String(entry.case_.expected.reason)}`);

  if (!result.ok) return result;
  // SAFETY: narrowing barrier; the expectations above fail the test first.
  throw new Error('Verification result was not a failure.');
}

async function verifiedSuccess(entry: CorpusEntry): Promise<VerificationSuccess> {
  const result = await verify(requestFor(entry), fixtureOptions(entry.provider, entry.case_));

  expect(`${entry.provider}/${entry.case_.id} ok=${String(result.ok)}`).toBe(
    `${entry.provider}/${entry.case_.id} ok=true`);

  if (result.ok) return result;
  // SAFETY: narrowing barrier; the expectation above fails the test first.
  throw new Error('Verification result was not a success.');
}

function canaryTokens(tag: string): readonly string[] {
  return ['message', 'cause', 'body', 'header', 'secret', 'signature', 'id'].map((role) => `${tag}:${role}`);
}

function requireDetail(diagnostic: Diagnostic): NonNullable<Diagnostic['detail']> {
  const detail = diagnostic.detail;

  if (detail === undefined) throw new Error('Expected verbose provider detail on the diagnostic.');

  return detail;
}

function expectPinnedDetail(diagnostic: Diagnostic, provider: BaselineProvider): void {
  const detail = requireDetail(diagnostic);
  const expectation = PROVIDER_DETAIL_EXPECTATIONS[provider];

  expect([...detail.expectedHeaders]).toEqual([...expectation.expectedHeaders]);

  for (const fragment of expectation.grammarIncludes) expect(detail.grammar).toContain(fragment);
}

describe('six-provider fixture corpus', () => {
  test('the registry, inventory counts and pinned verification outcomes all hold', async () => {
    expect(SUPPORTED_PROVIDERS.slice(0, PINNED_PROVIDER_ORDER.length)).toEqual([...PINNED_PROVIDER_ORDER]);
    expect(CORPUS).toHaveLength(PINNED_CASE_COUNTS.total);

    expect(CORPUS.filter((entry) => entry.provider === 'clerk')).toHaveLength(PINNED_CASE_COUNTS.clerk);
    expect(CORPUS.filter((entry) => entry.provider === 'svix')).toHaveLength(PINNED_CASE_COUNTS.svix);
    expect(CORPUS.filter((entry) => entry.provider !== 'clerk' && entry.provider !== 'svix'))
      .toHaveLength(PINNED_CASE_COUNTS.legacy);

    for (const entry of CORPUS) {
      const result = await verify(requestFor(entry), fixtureOptions(entry.provider, entry.case_));
      const label = `${entry.provider}/${entry.case_.id}`;

      expect(`${label} ok=${String(result.ok)}`).toBe(`${label} ok=${String(entry.case_.expected.ok)}`);

      if (!result.ok) {
        expect(`${label} reason=${result.reason}`).toBe(`${label} reason=${String(entry.case_.expected.reason)}`);
      }
    }
  });
});

describe('diagnostics for reasons the fixture corpus does not cover', () => {
  test('diagnoses a real missing-timestamp failure', async () => {
    const result = await verify(
      {
        rawBody: new TextEncoder().encode('synthetic'),
        headers: {
          'svix-id': 'msg_synthetic_diagnostic01',
          'svix-signature': 'v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=',
        },
      },
      { provider: 'svix', secrets: ['whsec_MDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1u'], now: () => 1614265330 },
    );

    expect(result.ok).toBe(false);
    expect(result.ok ? 'none' : result.reason).toBe('missing-timestamp');

    if (result.ok) throw new Error('Expected a failing verification result.');

    const cleanDiagnostic = diagnose(result, { provider: 'svix', verbose: true });
    const diagnostic = diagnose(result, { provider: 'svix', verbose: true });

    expect(diagnostic.code).toBe('missing-timestamp');
    expect(diagnostic.kind).toBe('verification');
    expect(diagnostic.provider).toBe('svix');
    expectPinnedDetail(diagnostic, 'svix');
    expect(JSON.stringify(diagnose(result, { provider: 'svix', verbose: true }))).toBe(JSON.stringify(diagnostic));

    const tag = 'hz-canary/synthetic/missing-timestamp';
    const tokens = canaryTokens(tag);

    const tainted = {
      ...result,
      message: `${tag}:message`,
      cause: `${tag}:cause`,
      body: `${tag}:body`,
      headers: { 'x-canary': `${tag}:header` },
      secrets: [`${tag}:secret`],
      signature: `${tag}:signature`,
      id: `${tag}:id`,
    };

    // SAFETY: deliberately over-shaped input extends past the typed failure
    // API to prove unknown fields are ignored, never coerced or echoed.
    const taintedDiagnostic = diagnose(tainted as never, { provider: 'svix', verbose: true });

    expect(taintedDiagnostic).toEqual(cleanDiagnostic);

    for (const token of tokens) expect(JSON.stringify(taintedDiagnostic)).not.toContain(token);
  });

  test('diagnoses a real body-too-large failure', async () => {
    const result = await verify(
      {
        rawBody: new TextEncoder().encode('0123456789'),
        headers: { 'x-hub-signature-256': `sha256=${'0'.repeat(64)}` },
      },
      { provider: 'github', secrets: ['github_synthetic_empty'], maxBodyBytes: 1, now: () => 1614265330 },
    );

    expect(result.ok).toBe(false);
    expect(result.ok ? 'none' : result.reason).toBe('body-too-large');

    if (result.ok) throw new Error('Expected a failing verification result.');

    const diagnostic = diagnose(result, { provider: 'github', verbose: true });

    expect(diagnostic.code).toBe('body-too-large');
    expect(diagnostic.kind).toBe('verification');
    expect(diagnostic.provider).toBe('github');
    expectPinnedDetail(diagnostic, 'github');

    expect(JSON.stringify(diagnose(result, { provider: 'github', verbose: true }))).toBe(JSON.stringify(diagnostic));
  });
});

describe('diagnostics for real verification failures', () => {
  test.each(EXPECTED_FAILURES.map((entry) => [entry.provider, entry.case_.id, entry] as const))(
    '%s · %s exposes a static, provider-specific diagnostic',
    async (provider, _caseId, entry) => {
      const failure = await verifiedFailure(entry);
      const diagnostic = diagnose(failure, { provider, verbose: true });

      expect(diagnostic.code).toBe(failure.reason);
      expect(diagnostic.kind).toBe('verification');
      expect(diagnostic.provider).toBe(provider);

      expectPinnedDetail(diagnostic, provider);

      expect(diagnostic.summary.length).toBeGreaterThan(0);
      expect(diagnostic.possibleCauses.length).toBeGreaterThan(0);
      expect(diagnostic.suggestions.length).toBeGreaterThan(0);
      expect(diagnostic).not.toHaveProperty('message');

      const expectedKeys = ['code', 'kind', 'possibleCauses', 'summary', 'suggestions'];

      if (diagnostic.provider !== undefined) expectedKeys.push('provider');

      if (diagnostic.detail !== undefined) expectedKeys.push('detail');

      expect(Object.keys(diagnostic).sort()).toEqual(expectedKeys.sort());

      expect(JSON.stringify(diagnose(failure, { provider, verbose: true })))
        .toBe(JSON.stringify(diagnostic));

      expect(diagnose(failure).detail).toBeUndefined();
      expect(diagnose(failure).kind).toBe('verification');
      expect(diagnose(failure).provider).toBe(provider);

      // Failure inputs carry their provider, so verbose detail does not require
      // an explicit provider option: it is derived from the failure itself.
      const verboseOnly = diagnose(failure, { verbose: true });

      expect(verboseOnly.kind).toBe('verification');
      expect(verboseOnly.provider).toBe(failure.provider);
      expectPinnedDetail(verboseOnly, provider);
    },
  );

  test.each(EXPECTED_FAILURES.map((entry) => [entry.provider, entry.case_.id, entry] as const))(
    '%s · %s diagnostics must not disclose tainted extra fields',
    async (provider, caseId, entry) => {
      const failure = await verifiedFailure(entry);
      const cleanDiagnostic = diagnose(failure, { provider, verbose: true });
      const tag = `hz-canary/${provider}/${caseId}`;
      const tokens = canaryTokens(tag);

      const tainted = {
        ...failure,
        message: `${tag}:message`,
        cause: `${tag}:cause`,
        body: `${tag}:body`,
        headers: { 'x-canary': `${tag}:header` },
        secrets: [`${tag}:secret`],
        signature: `${tag}:signature`,
        id: `${tag}:id`,
      };

      // SAFETY: deliberately over-shaped input extends past the typed failure
      // API to prove unknown fields are ignored, never coerced or echoed.
      const taintedDiagnostic = diagnose(tainted as never, { provider, verbose: true });

      expect(taintedDiagnostic).toEqual(cleanDiagnostic);

      const serialized = JSON.stringify(taintedDiagnostic);

      expect(serialized).toBeDefined();

      for (const token of tokens) expect(serialized).not.toContain(token);
    },
  );

  test('a provider option that mismatches the failure provider is rejected for all six providers', () => {
    for (const provider of PINNED_PROVIDER_ORDER) {
      const failure: VerificationFailure = { ok: false, provider, reason: 'invalid-signature', message: 'synthetic' };
      const mismatched = MISMATCH_FOR[provider];

      expect(() => diagnose(failure, { provider: mismatched }))
        .toThrow(expect.objectContaining({ code: 'invalid-input' }));

      const diagnostic = diagnose(failure, { provider });

      expect(diagnostic.code).toBe('invalid-signature');
      expect(diagnostic.kind).toBe('verification');
      expect(diagnostic.provider).toBe(provider);
      expect(diagnostic.detail).toBeUndefined();
    }
  });
});

describe('diagnostics for setup errors', () => {
  test.each(SETUP_CODES.map((code) => [code] as const))('%s exposes static setup guidance', (code) => {
    const provider = SETUP_PROVIDER_BY_CODE[code];
    const tag = `hz-canary/setup/${code}`;
    const tokens = canaryTokens(tag);

    const error = new HooklatchError(code, `${tag}:message`);
    error.cause = {
      body: `${tag}:body`,
      headers: { 'x-canary': `${tag}:header` },
      secrets: [`${tag}:secret`],
      signature: `${tag}:signature`,
      id: `${tag}:id`,
    };

    const verbose = diagnose(error, { provider, verbose: true });

    expect(verbose.code).toBe(code);
    expect(verbose.kind).toBe('setup');
    expect(verbose.provider).toBe(provider);
    expectPinnedDetail(verbose, provider);

    expect(verbose.summary.length).toBeGreaterThan(0);
    expect(verbose.possibleCauses.length).toBeGreaterThan(0);
    expect(verbose.suggestions.length).toBeGreaterThan(0);
    expect(verbose).not.toHaveProperty('message');

    const plain = diagnose(error);

    expect(plain.code).toBe(code);
    expect(plain.kind).toBe('setup');
    expect(plain).not.toHaveProperty('provider');
    expect(plain).not.toHaveProperty('message');
    expect(plain.detail).toBeUndefined();

    expect(JSON.stringify(diagnose(error, { provider, verbose: true }))).toBe(JSON.stringify(verbose));

    for (const diagnostic of [verbose, plain]) {
      const serialized = JSON.stringify(diagnostic);

      expect(serialized).toBeDefined();

      for (const token of tokens) expect(serialized).not.toContain(token);
    }
  });
});

describe('diagnostic input validation', () => {
  test('rejects every verification reason offered as a setup code', () => {
    for (const reason of VERIFICATION_REASONS) {
      // SAFETY: deliberately incorrect code value exercises runtime rejection.
      expect(() => diagnose(new HooklatchError(reason as never, 'synthetic')))
        .toThrow(expect.objectContaining({ code: 'invalid-input' }));
    }
  });

  test('rejects every setup code offered as a verification failure reason', () => {
    for (const code of SETUP_CODES) {
      // SAFETY: deliberately incorrect reason value exercises runtime rejection.
      const bogus: VerificationFailure = { ok: false, provider: 'svix', reason: code as never, message: 'synthetic' };

      expect(() => diagnose(bogus)).toThrow(expect.objectContaining({ code: 'invalid-input' }));
    }
  });

  test('rejects coercible or structured reason values for every verification reason', () => {
    for (const reason of VERIFICATION_REASONS) {
      for (const wrapper of [{ toString: () => reason, secret: 'hz-canary/wrapper' }, [reason]]) {
        // SAFETY: deliberately malformed reason widens past the typed API.
        const bogus: VerificationFailure = { ok: false, provider: 'shopify', reason: wrapper as never, message: 'synthetic' };

        expect(() => diagnose(bogus)).toThrow(expect.objectContaining({ code: 'invalid-input' }));
      }
    }
  });

  test('rejects failures whose reason accessors throw', () => {
    // SAFETY: a throwing accessor exercises the untrusted-accessor path.
    const hostile = {
      ok: false as const,
      provider: 'clerk' as const,
      message: 'synthetic',
      get reason(): string {
        throw new Error('getter-guard');
      },
    };

    // SAFETY: a throwing accessor must be contained by the output-fallback
    // path; its error text (getter-guard) never reaches the diagnostic.
    expect(() => diagnose(hostile as never)).toThrow(expect.objectContaining({ code: 'invalid-input' }));
  });

  test('rejects every successful verification result as a diagnostic failure', async () => {
    expect(EXPECTED_SUCCESSES.length).toBeGreaterThan(0);

    for (const entry of EXPECTED_SUCCESSES) {
      const success = await verifiedSuccess(entry);

      // SAFETY: successful results must never coerce into a failure diagnostic.
      expect(() => diagnose(success as never, { provider: entry.provider, verbose: true }))
        .toThrow(expect.objectContaining({ code: 'invalid-input' }));
    }
  });
});
