import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { existsSync, readdirSync } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const npmCli = process.env.npm_execpath;

assert(npmCli, 'Run this check via npm run test:package.');

const manifest = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));

// Required fixture coverage is derived from the built registry, so registering
// a provider with its fixture extends the installed-package matrix without
// editing this harness. No public registry export is added or assumed.
const registryPath = join(root, 'dist', 'providers', 'index.js');

if (!existsSync(registryPath)) {
  throw new Error('Built provider registry is missing: dist/providers/index.js. Run npm run build before npm run test:package.');
}

const { SUPPORTED_PROVIDERS } = await import(pathToFileURL(registryPath).href);

assert(Array.isArray(SUPPORTED_PROVIDERS) && SUPPORTED_PROVIDERS.length > 0,
  'The built registry did not expose a nonempty SUPPORTED_PROVIDERS array.');

const EXPECTED_PROVIDER_ORDER = [
  'stripe',
  'github',
  'shopify',
  'standard-webhooks',
  'clerk',
  'svix',
  'razorpay',
  'paddle',
  'lemon-squeezy',
  'dodo-payments',
  'gitlab',
  'replicate',
  'workos',
  'sentry',
  'doppler',
  'sanity',
  'grafana',
  'polar',
  'linear',
  'vercel',
  'fal',
];

const TARGET_PROVIDERS = EXPECTED_PROVIDER_ORDER.length;
const NEW_PROVIDERS = ['vercel', 'fal'];
const EXIT_NOT_READY = 3;
const FAL_PUBLIC_KEY_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/**
 * Explicit header names for the legacy `unsigned-or-null` identity sentinel.
 * A sentinel for any provider absent here fails loudly instead of guessing, so
 * a new canonical family or WorkOS is never treated as an old provider.
 */
const SENTINEL_HEADER = {
  github: { deliveryId: 'x-github-delivery' },
  shopify: { deliveryId: 'x-shopify-webhook-id', eventId: 'x-shopify-event-id' },
  razorpay: { eventId: 'x-razorpay-event-id' },
};

/**
 * Provider-option keys a fixture may supply. Configuration for the existing
 * providers is forbidden by the public options union, so anything else fails
 * here rather than being silently dropped on the way to the installed SDK.
 */
const CONFIGURED_PROVIDER_KEYS = {
  grafana: ['mode', 'signatureHeader', 'timestampHeader'],
  polar: ['secretMode'],
};

const GRAFANA_MODES = ['body', 'timestamped'];
const POLAR_SECRET_MODES = ['current', 'legacy'];
const FIELD_NAME_TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

/**
 * JSON boundary kind for parsed fixture data. This is the I/O-boundary parse
 * step used instead of ad-hoc `typeof` narrowing, which the repository's
 * anti-slop rules forbid outside type guards.
 */
function jsonKind(value) {
  return Object.prototype.toString.call(value).slice(8, -1);
}

function requireKind(value, kind, label) {
  assert.equal(jsonKind(value), kind, `${label} must be a JSON ${kind.toLowerCase()}.`);

  return value;
}

function isPlainRecord(value) {
  return jsonKind(value) === 'Object';
}

function requireHeaderName(value, label) {
  requireKind(value, 'String', label);
  assert(FIELD_NAME_TOKEN.test(value), `${label} is not an RFC9110 field-name token: ${JSON.stringify(value)}.`);
}

function isCallable(value) {
  return value instanceof Function;
}

function syntheticFalPublicKey() {
  const jwk = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' });

  assert.equal(jwk.kty, 'OKP');
  assert.equal(jwk.crv, 'Ed25519');
  requireKind(jwk.x, 'String', 'Synthetic Ed25519 public JWK x');

  const bytes = Buffer.from(jwk.x, 'base64url');

  assert.equal(bytes.length, 32, 'Synthetic Ed25519 public key must be 32 bytes.');

  return new Uint8Array(bytes);
}

/** Strict fixture-only decoder; the installed API receives raw 32-byte keys. */
function decodeCanonicalFalKey(value, label) {
  const encoded = requireKind(value, 'String', label);

  assert(FAL_PUBLIC_KEY_PATTERN.test(encoded), `${label} must be exactly 43 unpadded Base64url characters.`);

  const decoded = Buffer.from(encoded, 'base64url');

  assert.equal(decoded.length, 32, `${label} must encode exactly 32 visible bytes.`);
  assert.equal(decoded.toString('base64url'), encoded,
    `${label} is not canonical Base64url (padding, whitespace, or noncanonical unused bits).`);

  return [...decoded];
}

function requireFalUserId(value, label) {
  const id = requireKind(value, 'String', label);

  assert(/^[\x21-\x7e]{1,1024}$/.test(id) && !id.includes(','),
    `${label} must be 1-1024 visible ASCII characters excluding comma.`);

  return id;
}

function decideRegistryReadiness(providers) {
  if (providers.length !== TARGET_PROVIDERS) {
    return {
      ready: false,
      reason: `Built registry has ${providers.length} providers; the reviewed Phase 9 target is ${TARGET_PROVIDERS}.`,
    };
  }

  for (const [index, expected] of EXPECTED_PROVIDER_ORDER.entries()) {
    if (providers[index] !== expected) {
      return {
        ready: false,
        reason: `Built registry provider ${index} is ${JSON.stringify(providers[index])}; expected ${JSON.stringify(expected)}.`,
      };
    }
  }

  return { ready: true, reason: '' };
}

function requireNewFixtures() {
  const missing = NEW_PROVIDERS.filter((provider) => !existsSync(join(root, 'tests', 'fixtures', `${provider}.json`)));

  return missing.length === 0
    ? { ready: true, reason: '' }
    : { ready: false, reason: `Reviewed fixtures are missing: ${missing.map((provider) => `tests/fixtures/${provider}.json`).join(', ')}.` };
}

async function inspectBuiltApiReadiness() {
  try {
    const api = await import(pathToFileURL(join(root, 'dist', 'index.js')).href);
    const diagnostics = await import(pathToFileURL(join(root, 'dist', 'diagnostics', 'index.js')).href);

    for (const name of ['verify', 'createVerifier', 'verifyRequest']) {
      if (!isCallable(api[name])) return { ready: false, reason: `Built public API is missing callable ${name}.` };
    }

    if (!isCallable(diagnostics.diagnose)) {
      return { ready: false, reason: 'Built diagnostics API is missing callable diagnose.' };
    }

    const vercelVerifier = api.createVerifier({ provider: 'vercel', secrets: ['synthetic-vercel-secret'] });

    const falVerifier = api.createVerifier({
      provider: 'fal',
      publicKeys: [syntheticFalPublicKey()],
      expectedUserId: 'user_synthetic_package',
    });

    if (!isCallable(vercelVerifier) || !isCallable(falVerifier)) {
      return { ready: false, reason: 'Built createVerifier did not return callable verifiers for vercel/fal.' };
    }

    return { ready: true, reason: '' };
  } catch (error) {
    return {
      ready: false,
      reason: `Built API rejected the reviewed vercel/fal credential arms: ${error instanceof Error ? error.message : String(error)}.`,
    };
  }
}

function inspectBuiltCliReadiness() {
  const cli = join(root, 'dist', 'cli', 'index.js');

  if (!existsSync(cli)) return { ready: false, reason: 'Built CLI is missing: dist/cli/index.js.' };

  try {
    const help = execFileSync(process.execPath, [cli, '--help'], {
      cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
    });

    const missing = ['--secret-env', '--public-key-env', '--expected-user-env'].filter((flag) => !help.includes(flag));

    return missing.length === 0
      ? { ready: true, reason: '' }
      : { ready: false, reason: `Built CLI help is missing credential flag(s): ${missing.join(', ')}.` };
  } catch (error) {
    return { ready: false, reason: `Built CLI help failed: ${error instanceof Error ? error.message : String(error)}.` };
  }
}

/**
 * All readiness gates run before pack/install/temp allocation. A 19-provider
 * base is a prerequisite stop (exit 3), never a passing installed-package run.
 */
const registryReadiness = decideRegistryReadiness(SUPPORTED_PROVIDERS);

if (!registryReadiness.ready) {
  console.error(`BLOCKED (exit ${EXIT_NOT_READY}): ${registryReadiness.reason} No pack, install or temp allocation was performed.`);
  process.exit(EXIT_NOT_READY);
}

const fixtureReadiness = requireNewFixtures();

if (!fixtureReadiness.ready) {
  console.error(`BLOCKED (exit ${EXIT_NOT_READY}): ${fixtureReadiness.reason} No pack, install or temp allocation was performed.`);
  process.exit(EXIT_NOT_READY);
}

const apiReadiness = await inspectBuiltApiReadiness();

if (!apiReadiness.ready) {
  console.error(`BLOCKED (exit ${EXIT_NOT_READY}): ${apiReadiness.reason} No pack, install or temp allocation was performed.`);
  process.exit(EXIT_NOT_READY);
}

const cliReadiness = inspectBuiltCliReadiness();

if (!cliReadiness.ready) {
  console.error(`BLOCKED (exit ${EXIT_NOT_READY}): ${cliReadiness.reason} No pack, install or temp allocation was performed.`);
  process.exit(EXIT_NOT_READY);
}

function validateFixtureProviderOptions(provider, value, label) {
  if (value === undefined) return;

  assert(isPlainRecord(value), `${label}: providerOptions must be a non-array object.`);

  const allowed = CONFIGURED_PROVIDER_KEYS[provider];

  assert(allowed !== undefined,
    `${label}: providerOptions is only valid for configured providers; the public options union forbids it for ${provider}.`);

  for (const key of Object.keys(value)) {
    assert(allowed.includes(key), `${label}: unexpected providerOptions key ${JSON.stringify(key)}.`);
    assert.notEqual(value[key], undefined, `${label}: providerOptions.${key} must be a defined own value; omit it instead.`);
  }

  if (provider === 'grafana') {
    assert(Object.hasOwn(value, 'mode'), `${label}: grafana providerOptions require an own mode.`);
    assert(GRAFANA_MODES.includes(value.mode),
      `${label}: grafana providerOptions.mode must be body or timestamped, got ${JSON.stringify(value.mode)}.`);

    if (Object.hasOwn(value, 'signatureHeader')) {
      requireHeaderName(value.signatureHeader, `${label}: providerOptions.signatureHeader`);
    }

    if (value.mode === 'body') {
      assert(!Object.hasOwn(value, 'timestampHeader'), `${label}: body mode must not carry timestampHeader.`);
    } else {
      assert(Object.hasOwn(value, 'timestampHeader'),
        `${label}: timestamped mode requires an own timestampHeader.`);
      requireHeaderName(value.timestampHeader, `${label}: providerOptions.timestampHeader`);
    }

    return;
  }

  if (Object.hasOwn(value, 'secretMode')) {
    assert(POLAR_SECRET_MODES.includes(value.secretMode),
      `${label}: polar providerOptions.secretMode must be current or legacy, got ${JSON.stringify(value.secretMode)}.`);
  }
}

/** Validate fixture rows at the boundary before they reach an SDK call. */
function validateFixtureCase(provider, fixture, label) {
  requireKind(fixture.id, 'String', `${label}: fixture id`);
  assert.notEqual(fixture.id.length, 0, `${label}: fixture id must be nonempty.`);
  assert(isPlainRecord(fixture.request), `${label}: request must be an object.`);

  const { bodyBase64 } = fixture.request;

  requireKind(bodyBase64, 'String', `${label}: request.bodyBase64`);
  // Exact bytes: a non-canonical encoding would replay bytes the author did not sign.
  assert.equal(Buffer.from(bodyBase64, 'base64').toString('base64'), bodyBase64,
    `${label}: request.bodyBase64 is not canonical padded Base64.`);

  assert(isPlainRecord(fixture.request.headers), `${label}: request.headers must be a record.`);

  for (const [name, value] of Object.entries(fixture.request.headers)) {
    assert(FIELD_NAME_TOKEN.test(name), `${label}: request header name ${JSON.stringify(name)} is not a field-name token.`);

    const values = Array.isArray(value) ? value : [value];

    assert(values.length > 0 && values.every((entry) => jsonKind(entry) === 'String'),
      `${label}: request header ${JSON.stringify(name)} must be a string or nonempty string array.`);
  }

  const options = fixture.options;

  assert(isPlainRecord(options), `${label}: options must be an object.`);

  const allowedKeys = provider === 'fal'
    ? ['publicKeysBase64url', 'expectedUserId', 'now', 'toleranceSeconds', 'maxBodyBytes']
    : ['secrets', 'now', 'toleranceSeconds', 'maxBodyBytes', 'providerOptions'];

  for (const key of Object.keys(options)) {
    assert(allowedKeys.includes(key), `${label}: unexpected options key ${JSON.stringify(key)}.`);
  }

  if (provider === 'fal') {
    assert(Array.isArray(options.publicKeysBase64url) && options.publicKeysBase64url.length >= 1
      && options.publicKeysBase64url.length <= 16,
    `${label}: options.publicKeysBase64url must contain 1-16 encoded trusted keys.`);

    for (const [index, encoded] of options.publicKeysBase64url.entries()) {
      decodeCanonicalFalKey(encoded, `${label}: options.publicKeysBase64url[${index}]`);
    }

    requireFalUserId(options.expectedUserId, `${label}: options.expectedUserId`);
  } else {
    assert(Array.isArray(options.secrets) && options.secrets.length > 0, `${label}: options.secrets must be a nonempty array.`);

    for (const secret of options.secrets) requireKind(secret, 'String', `${label}: each secret`);
  }

  // Fractional epoch seconds are legitimate existing freshness coverage.
  // Number.isFinite rejects non-number JSON kinds without a typeof branch.
  assert(Number.isFinite(options.now) && options.now >= 0,
    `${label}: options.now must be a fixed nonnegative finite epoch-second clock.`);

  if (options.toleranceSeconds !== undefined) {
    assert(Number.isSafeInteger(options.toleranceSeconds) && options.toleranceSeconds >= 0,
      `${label}: options.toleranceSeconds must be a nonnegative safe integer.`);
  }

  if (options.maxBodyBytes !== undefined) {
    assert(Number.isSafeInteger(options.maxBodyBytes) && options.maxBodyBytes > 0,
      `${label}: options.maxBodyBytes must be a positive safe integer.`);
  }

  if (provider !== 'fal') validateFixtureProviderOptions(provider, options.providerOptions, label);

  assert(isPlainRecord(fixture.expected), `${label}: expected must be an object.`);

  if (fixture.webHeadersExpected !== undefined) {
    assert(isPlainRecord(fixture.webHeadersExpected), `${label}: webHeadersExpected must be an object.`);
    // The record and WHATWG paths must assert different outcomes when a fixture
    // overrides; a duplicate override would hide which transport is covered.
    assert.notDeepEqual(fixture.webHeadersExpected, fixture.expected,
      `${label}: webHeadersExpected duplicates expected; remove the redundant override.`);
  }
}

/**
 * Configured fixture files whose provider the built registry does not expose
 * yet. Reported as dependency-pending; never silently skipped or counted.
 */
async function pendingConfiguredFixtureProviders() {
  const directory = join(root, 'tests', 'fixtures');
  const pending = [];

  for (const name of readdirSync(directory).sort()) {
    if (!name.endsWith('.json')) continue;

    const provider = name.slice(0, -'.json'.length);

    if (SUPPORTED_PROVIDERS.includes(provider)) continue;

    const file = JSON.parse(await readFile(join(directory, name), 'utf8'));

    const rows = Array.isArray(file.cases)
      ? file.cases.filter((entry) => entry?.options?.providerOptions !== undefined) : [];

    if (rows.length === 0) continue;

    for (const fixture of rows) validateFixtureCase(provider, fixture, `${provider} pending fixture ${fixture.id}`);

    pending.push({ provider, rows: rows.length });
  }

  return pending;
}

/**
 * Convert the fixture-only fal encoding into the raw Uint8Array[] shape the
 * installed API actually accepts. This is the only place the installed-package
 * harness decodes fal keys; no secret field is carried into the probe.
 */
function runtimeFixtureCase(provider, fixture) {
  if (provider !== 'fal') return fixture;

  const options = {
    publicKeys: fixture.options.publicKeysBase64url.map((encoded, index) => decodeCanonicalFalKey(
      encoded,
      `${provider} fixture ${fixture.id}: options.publicKeysBase64url[${index}]`,
    )),
    expectedUserId: fixture.options.expectedUserId,
    now: fixture.options.now,
  };

  if (fixture.options.toleranceSeconds !== undefined) options.toleranceSeconds = fixture.options.toleranceSeconds;

  if (fixture.options.maxBodyBytes !== undefined) options.maxBodyBytes = fixture.options.maxBodyBytes;

  return { ...fixture, options };
}

const providerFixtures = [];

for (const provider of SUPPORTED_PROVIDERS) {
  const path = join(root, 'tests', 'fixtures', `${provider}.json`);

  if (!existsSync(path)) {
    throw new Error(`Registered provider ${provider} has no fixture file: tests/fixtures/${provider}.json.`);
  }

  const { cases } = JSON.parse(await readFile(path, 'utf8'));

  assert(Array.isArray(cases) && cases.length > 0,
    `Fixture for ${provider} has no cases; installed-package coverage would silently shrink.`);
  assert(cases.some((entry) => entry.expected.ok && entry.request && entry.request.bodyBase64 !== undefined),
    `Fixture for ${provider} has no positive anchor (expected.ok with bodyBase64).`);

  for (const fixture of cases) validateFixtureCase(provider, fixture, `${provider} fixture ${fixture.id}`);

  providerFixtures.push({ provider, cases: cases.map((fixture) => runtimeFixtureCase(provider, fixture)) });
}

const pendingConfigured = await pendingConfiguredFixtureProviders();

if (pendingConfigured.length > 0) {
  const summary = pendingConfigured.map((entry) => `${entry.provider} (${entry.rows} rows)`).join(', ');

  console.log(`DEPENDENCY-PENDING: ${summary} configured fixture rows are outside the built registry; public registration is coordinator-owned, so these rows were not replayed and are not counted as covered.`);
}

function normalizePackagePath(path) {
  return path.startsWith('./') ? path.slice(2) : path;
}

function declaredEntrypoints(packageManifest) {
  const paths = new Set([
    requireKind(packageManifest.main, 'String', 'package.main'),
    requireKind(packageManifest.types, 'String', 'package.types'),
  ]);

  assert(isPlainRecord(packageManifest.exports), 'package.exports must be a record of conditional export targets.');

  for (const [name, target] of Object.entries(packageManifest.exports)) {
    assert(isPlainRecord(target), `package.exports[${JSON.stringify(name)}] must be a conditional target record.`);
    paths.add(requireKind(target.types, 'String', `package.exports[${JSON.stringify(name)}].types`));
    paths.add(requireKind(target.import, 'String', `package.exports[${JSON.stringify(name)}].import`));
  }

  assert(isPlainRecord(packageManifest.bin), 'package.bin must be a record.');

  for (const [name, target] of Object.entries(packageManifest.bin)) {
    paths.add(requireKind(target, 'String', `package.bin[${JSON.stringify(name)}]`));
  }

  return [...paths].map(normalizePackagePath).sort();
}

const entrypoints = declaredEntrypoints(manifest);

assert(entrypoints.length > 0, 'Package manifest declares no entrypoints.');

const missingEntrypoints = entrypoints.filter((path) => !existsSync(join(root, path)));

assert.equal(
  missingEntrypoints.length,
  0,
  `Missing required package entrypoint(s): ${missingEntrypoints.join(', ')}. `
    + 'Run npm run build before npm run test:package.',
);

const tempRoot = await mkdtemp(join(tmpdir(), 'hooklatch-package-'));

const npm = (args, cwd) => execFileSync(process.execPath, [npmCli, ...args], {
  cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
});

try {
  const [pack] = JSON.parse(npm(['pack', '--json', '--pack-destination', tempRoot], root));
  assert(pack.files.every(({ path }) => path.startsWith('dist/') || ['package.json', 'README.md', 'LICENSE'].includes(path)), 'Unexpected files in npm tarball.');
  const packedPaths = new Set(pack.files.map(({ path }) => path));

  for (const entrypoint of entrypoints) {
    assert(packedPaths.has(entrypoint), `Required package entrypoint is absent from the tarball: ${entrypoint}.`);
  }

  assert([...packedPaths].some((path) => path.startsWith('dist/')), 'Packed package contains no dist files.');
  assert.equal(Object.keys(manifest.dependencies ?? {}).length, 0);
  npm(['install', join(tempRoot, pack.filename), '--omit=dev', '--ignore-scripts', '--offline', '--no-audit', '--no-fund'], tempRoot);

  // A new process outside the workspace proves core loads without dev/framework deps.
  const check = `
    import assert from 'node:assert/strict';
    import { verify, verifyRequest, createVerifier, HooklatchError } from 'hooklatch';
    import { diagnose } from 'hooklatch/diagnostics';

    const diagnostic = diagnose({ ok: false, provider: 'clerk', reason: 'invalid-signature', message: 'PACKAGE_PRIVATE_CANARY' }, { verbose: true });
    assert.equal(diagnostic.code, 'invalid-signature');
    assert.equal(diagnostic.provider, 'clerk');
    assert(diagnostic.detail.expectedHeaders.includes('svix-signature'));
    assert(!JSON.stringify(diagnostic).includes('PACKAGE_PRIVATE_CANARY'));
    assert.throws(() => diagnose({ ok: false, provider: 'clerk', reason: { toString() { return 'invalid-signature'; }, secret: 'PACKAGE_PRIVATE_CANARY' } }), { code: 'invalid-input' });

    const encoder = new TextEncoder();
    const githubOptions = { provider: 'github', secrets: ["It's a Secret to Everybody"] };
    const githubHeaders = { 'x-hub-signature-256': 'sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17' };
    const githubInput = { rawBody: encoder.encode('Hello, World!'), headers: githubHeaders };
    assert.equal((await verify(githubInput, githubOptions)).ok, true);
    assert.equal((await createVerifier(githubOptions)(githubInput)).ok, true);
    assert.equal((await verifyRequest(new Request('https://example.test', { method: 'POST', headers: githubHeaders, body: 'Hello, World!' }), githubOptions)).ok, true);
    assert.equal((await verify({ ...githubInput, rawBody: encoder.encode('tampered') }, githubOptions)).ok, false);
    assert.equal(typeof HooklatchError, 'function');

    const secret = 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw';
    const id = 'msg_p5jXN8AQM9LWM0D4loKWxJek';
    const timestamp = 1614265330;
    const publishedBody = encoder.encode('{"test": 2432232314}');
    const signature = 'v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=';
    const identity = { deliveryId: null, eventId: id, timestamp, authenticatedFields: ['eventId', 'timestamp'] };
    const headersFor = (family) => family === 'svix'
      ? { 'svix-id': id, 'svix-timestamp': String(timestamp), 'svix-signature': signature }
      : { 'webhook-id': id, 'webhook-timestamp': String(timestamp), 'webhook-signature': signature };

    const checkPreset = async (provider, family) => {
      const headers = headersFor(family);
      const options = { provider, secrets: [secret], toleranceSeconds: 300, now: () => timestamp };
      const input = { rawBody: publishedBody, headers };
      const direct = await verify(input, options);
      assert.equal(direct.ok, true);
      assert.equal(direct.provider, provider);
      assert.deepEqual(direct.identity, identity);
      assert.deepEqual([...direct.rawBody], [...publishedBody]);

      const wrapped = await verifyRequest(new Request('https://example.test/hook', {
        method: 'POST', headers, body: publishedBody,
      }), options);
      assert.equal(wrapped.ok, true);
      assert.equal(wrapped.provider, provider);
      assert.deepEqual(wrapped.identity, identity);
      assert.deepEqual([...wrapped.rawBody], [...publishedBody]);

      const verifier = await createVerifier(options)(input);
      assert.equal(verifier.ok, true);
      assert.equal(verifier.provider, provider);
      assert.deepEqual([...verifier.rawBody], [...publishedBody]);
      assert.deepEqual(verifier.identity, identity);

      const tampered = await verify({ ...input, rawBody: encoder.encode('tampered') }, options);
      assert.equal(tampered.ok, false);
      assert.equal(tampered.reason, 'invalid-signature');
      console.log('PASS: packed ' + provider + ' verifies the published ' + family + ' vector and rejects tampering.');
    };

    await checkPreset('clerk', 'svix');
    await checkPreset('svix', 'svix');
    await checkPreset('svix', 'webhook');

    const providerFixtures = ${JSON.stringify(providerFixtures)};
    const sentinelHeader = ${JSON.stringify(SENTINEL_HEADER)};

    // HTTP folds repeated header values with ', '; mirror that on both the
    // direct record path and the Web Request path so array fixtures stay valid.
    const materialize = (headers) => Object.fromEntries(
      Object.entries(headers).map(([name, value]) => [name, Array.isArray(value) ? value.join(', ') : value]),
    );

    // Explicit public options: never spread the fixture record, so a new option
    // key cannot leak through unnoticed. fal receives decoded raw keys and its
    // required account field; no secret field is ever synthesized.
    const buildOptions = (provider, options) => {
      const built = provider === 'fal'
        ? {
          provider,
          publicKeys: options.publicKeys.map((bytes) => new Uint8Array(bytes)),
          expectedUserId: options.expectedUserId,
          now: () => options.now,
        }
        : { provider, secrets: options.secrets, now: () => options.now };

      if (options.toleranceSeconds !== undefined) built.toleranceSeconds = options.toleranceSeconds;
      if (options.maxBodyBytes !== undefined) built.maxBodyBytes = options.maxBodyBytes;
      if (provider !== 'fal' && options.providerOptions !== undefined) built.providerOptions = options.providerOptions;

      return built;
    };

    const lookupHeader = (headers, name) => {
      const wanted = name.toLowerCase();
      const entry = Object.entries(headers).find(([key]) => key.toLowerCase() === wanted);

      return entry === undefined ? null : entry[1];
    };

    const resolveIdentity = (provider, expected, headers, webTransport) => {
      const resolved = { ...expected };

      for (const field of ['deliveryId', 'eventId']) {
        if (resolved[field] !== 'unsigned-or-null') continue;
        const headerName = (sentinelHeader[provider] ?? {})[field];

        if (!headerName) throw new Error('Unhandled unsigned-or-null sentinel for ' + provider + '.' + field + '.');

        resolved[field] = webTransport
          ? new Headers(headers).get(headerName)
          : lookupHeader(headers, headerName);
      }

      return resolved;
    };

    const transportRejected = new Set([
      'id-grammar-user-id-with-unicode', 'id-grammar-user-id-crlf',
      'id-grammar-user-id-nul-byte', 'ts-grammar-unicode-digit-malformed',
    ]);
    const observedTransportRejections = new Set();

    for (const { provider, cases } of providerFixtures) {
      for (const fixture of cases) {
        const headers = materialize(fixture.request.headers);
        const rawBody = new Uint8Array(Buffer.from(fixture.request.bodyBase64, 'base64'));
        const options = buildOptions(provider, fixture.options);
        const input = { rawBody, headers };
        const label = provider + ':' + fixture.id;

        const assertResult = (result, webTransport) => {
          const expected = webTransport ? (fixture.webHeadersExpected ?? fixture.expected) : fixture.expected;
          assert.equal(result.ok, expected.ok, label);
          assert.equal(result.provider, provider, label);

          if (!result.ok) {
            assert.equal(result.reason, expected.reason, label);
            const failureDiagnostic = diagnose(result, { verbose: true });
            assert.equal(failureDiagnostic.provider, provider);
            assert.equal(failureDiagnostic.code, expected.reason);
            if (provider === 'grafana') {
              assert.deepEqual(failureDiagnostic.detail.expectedHeaders, []);
              assert.match(failureDiagnostic.detail.grammar, /configured signature header/i);
              assert.match(failureDiagnostic.detail.grammar, /timestamped/i);
            } else {
              assert(failureDiagnostic.detail.expectedHeaders.length > 0);
            }
            return;
          }

          const resolved = resolveIdentity(provider, expected.identity, headers, webTransport);
          assert.deepEqual(result.identity, resolved, label);
          assert.deepEqual([...result.rawBody], [...rawBody], label);
        };

        assertResult(await verify(input, options), false);
        assertResult(await createVerifier(options)(input), false);
        assertResult(await verify({ rawBody, headers: Object.entries(headers) }, options), false);

        if (provider === 'fal' && transportRejected.has(fixture.id)) {
          assert.throws(() => new Headers(headers), TypeError, label + ': HTTP must reject this raw header');
          observedTransportRejections.add(fixture.id);
        } else {
          assertResult(await verifyRequest(new Request('https://example.test/hook', {
            method: 'POST', headers, body: rawBody,
          }), options), true);
        }

        if (fixture.expected.ok) {
          const backing = new Uint8Array(rawBody.length + 2);

          backing.set(rawBody, 2);

          const offsetBody = backing.subarray(2, 2 + rawBody.length);
          const offsetResult = await verify({ rawBody: offsetBody, headers }, options);

          assertResult(offsetResult, false);

          const changed = new Uint8Array(rawBody.length + 1);
          changed.set(rawBody);
          changed[rawBody.length] = 33;
          const tampered = await verify({ ...input, rawBody: changed }, options);
          assert.equal(tampered.ok, false);
          assert.equal(tampered.reason, 'invalid-signature');
        }
      }

      console.log('PASS: packed ' + provider + ' corpus passes direct APIs, representable Request cases, metadata, diagnostics and tamper rejection.');

      const configured = cases.filter((fixture) => fixture.options.providerOptions !== undefined);

      if (configured.length > 0) {
        const anchor = configured.find((fixture) => fixture.expected.ok);

        assert(anchor, 'Configured provider ' + provider + ' has no successful anchor row.');

        const anchorHeaders = materialize(anchor.request.headers);
        const anchorBody = new Uint8Array(Buffer.from(anchor.request.bodyBase64, 'base64'));
        const anchorInput = { rawBody: anchorBody, headers: anchorHeaders };

        // An ignored providerOptions field would also ignore this unexpected own
        // key; contract setup validation must reject it as invalid-options. The
        // provider's custom-header/mode rows above independently prove that the
        // configured values reach parsing rather than being dropped.
        await assert.rejects(
          async () => verify(anchorInput, buildOptions(provider, {
            ...anchor.options,
            providerOptions: { ...anchor.options.providerOptions, hooklatch_unexpected_option: true },
          })),
          { code: 'invalid-options' },
        );

        if (provider === 'grafana') {
          const withoutConfig = { ...anchor.options };

          delete withoutConfig.providerOptions;
          await assert.rejects(async () => verify(anchorInput, buildOptions(provider, withoutConfig)),
            { code: 'invalid-options' });
          console.log('PASS: packed grafana requires providerOptions and rejects unknown option keys.');
        } else {
          console.log('PASS: packed ' + provider + ' rejects unknown providerOptions keys.');
        }
      }
    }

    const falKey = new Uint8Array(${JSON.stringify([...syntheticFalPublicKey()])});
    const falBase = { provider: 'fal', publicKeys: [falKey], expectedUserId: 'user_synthetic_setup' };

    const rejectInvalidSetup = async (label, options) => {
      await assert.rejects(
        async () => verify({ rawBody: new Uint8Array(0), headers: {} }, options),
        { code: 'invalid-options' },
        'Installed API accepted invalid setup: ' + label + '.',
      );
    };

    await rejectInvalidSetup('fal secrets', { ...falBase, secrets: ['synthetic'] });
    await rejectInvalidSetup('fal missing expectedUserId', { provider: 'fal', publicKeys: [falKey] });
    await rejectInvalidSetup('fal empty publicKeys', { provider: 'fal', publicKeys: [], expectedUserId: 'user_synthetic_setup' });
    await rejectInvalidSetup('fal 17 publicKeys', {
      provider: 'fal', publicKeys: Array.from({ length: 17 }, () => falKey), expectedUserId: 'user_synthetic_setup',
    });
    await rejectInvalidSetup('fal 31-byte key', { provider: 'fal', publicKeys: [new Uint8Array(31)], expectedUserId: 'user_synthetic_setup' });
    await rejectInvalidSetup('fal string key', { provider: 'fal', publicKeys: ['not-bytes'], expectedUserId: 'user_synthetic_setup' });
    await rejectInvalidSetup('vercel publicKeys', { provider: 'vercel', secrets: ['synthetic'], publicKeys: [falKey] });
    await rejectInvalidSetup('vercel expectedUserId', { provider: 'vercel', secrets: ['synthetic'], expectedUserId: 'user_synthetic_setup' });
    await rejectInvalidSetup('vercel providerOptions', {
      provider: 'vercel', secrets: ['synthetic'], providerOptions: { mode: 'body' },
    });

    for (const name of ['express', 'hono']) {
      await assert.rejects(import(name), { code: 'ERR_MODULE_NOT_FOUND' });
    }
    assert.deepEqual([...observedTransportRejections].sort(), [...transportRejected].sort());
    console.log('PASS: all four unrepresentable fal headers rejected by HTTP; direct record/tuple/factory results verified.');
    console.log('PASS: packed core imports and verifies offline without optional frameworks.');
  `;

  // A real temporary module avoids Windows command-line limits when the full
  // attributed corpus is embedded, and resolves imports from the consumer.
  const probePath = join(tempRoot, 'installed-package-probe.mjs');

  await writeFile(probePath, check);
  process.stdout.write(execFileSync(process.execPath, [probePath], { cwd: tempRoot, encoding: 'utf8' }));

  const installedRoot = join(tempRoot, 'node_modules', 'hooklatch');
  const installedManifest = JSON.parse(await readFile(join(installedRoot, 'package.json'), 'utf8'));
  const cli = join(installedRoot, installedManifest.bin.hooklatch);
  assert((await readFile(cli, 'utf8')).startsWith('#!/usr/bin/env node'));
  const installedBin = join(tempRoot, 'node_modules', '.bin', process.platform === 'win32' ? 'hooklatch.cmd' : 'hooklatch');
  assert(existsSync(installedBin), 'Installed CLI bin shim is missing.');
  const invoke = (args) => execFileSync(process.execPath, [cli, ...args], { cwd: tempRoot, encoding: 'utf8' });

  const invokeResult = (args) => {
    try {
      return { status: 0, stdout: invoke(args), stderr: '' };
    } catch (error) {
      return {
        status: error.status,
        stdout: String(error.stdout ?? ''),
        stderr: String(error.stderr ?? ''),
      };
    }
  };

  const help = invoke(['--help']);
  assert(help.includes('Usage: hooklatch'));
  assert(help.includes('--public-key-env'));
  assert(help.includes('--expected-user-env'));
  assert(invoke(['init', 'webhook', '--help']).includes('--dry-run'));
  const preview = invoke(['init', 'webhook', '--provider', 'standard-webhooks', '--framework', 'express', '--out', 'preview', '--dry-run']);
  assert(preview.includes('standard_webhooksExpressWebhook'));
  assert.equal(existsSync(join(tempRoot, 'preview')), false);

  for (const [provider, secretEnv] of [
    ['razorpay', 'RAZORPAY_WEBHOOK_SECRET'],
    ['paddle', 'PADDLE_WEBHOOK_SECRET'],
    ['lemon-squeezy', 'LEMON_SQUEEZY_WEBHOOK_SECRET'],
    ['dodo-payments', 'DODO_WEBHOOK_SECRET'],
    ['gitlab', 'GITLAB_WEBHOOK_SECRET'],
    ['replicate', 'REPLICATE_WEBHOOK_SECRET'],
    ['workos', 'WORKOS_WEBHOOK_SECRET'],
    ['sentry', 'SENTRY_WEBHOOK_SECRET'],
    ['doppler', 'DOPPLER_WEBHOOK_SECRET'],
    ['sanity', 'SANITY_WEBHOOK_SECRET'],
    ['vercel', 'VERCEL_WEBHOOK_SECRET'],
  ]) {
    const output = `preview-${provider}`;
    const content = invoke(['init', 'webhook', '--provider', provider, '--framework', 'express', '--out', output, '--dry-run']);
    assert(content.includes(`provider: '${provider}'`));
    assert(content.includes(`process.env.${secretEnv}!`));
    assert.equal(existsSync(join(tempRoot, output)), false);
  }

  const falOutput = 'preview-fal';
  const falPreview = invoke(['init', 'webhook', '--provider', 'fal', '--framework', 'express', '--out', falOutput, '--dry-run']);
  assert(falPreview.includes("provider: 'fal'"));
  assert(/\bpublicKeys\b/.test(falPreview));
  assert(/\bexpectedUserId\b/.test(falPreview));
  assert(falPreview.includes('process.env.FAL_WEBHOOK_PUBLIC_KEYS'));
  assert(falPreview.includes('process.env.FAL_WEBHOOK_USER_ID'));
  assert(!/\b(?:process\.env|env)\.FAL_WEBHOOK_SECRET\b/.test(falPreview));
  assert(!/\bsecrets?\s*:/.test(falPreview));
  assert.equal(existsSync(join(tempRoot, falOutput)), false);

  const falCustomOutput = 'preview-fal-custom';

  const falCustom = invoke([
    'init', 'webhook', '--provider', 'fal', '--framework', 'express', '--out', falCustomOutput,
    '--public-key-env', 'CUSTOM_FAL_PUBLIC_KEYS', '--expected-user-env', 'CUSTOM_FAL_USER_ID', '--dry-run',
  ]);

  assert(falCustom.includes('process.env.CUSTOM_FAL_PUBLIC_KEYS'));
  assert(falCustom.includes('process.env.CUSTOM_FAL_USER_ID'));
  assert(!falCustom.includes('FAL_WEBHOOK_PUBLIC_KEYS'));
  assert(!falCustom.includes('FAL_WEBHOOK_USER_ID'));
  assert.equal(existsSync(join(tempRoot, falCustomOutput)), false);

  const forbiddenSecret = invokeResult([
    'init', 'webhook', '--provider', 'fal', '--framework', 'express', '--out', 'preview-fal-forbidden',
    '--secret-env', 'FAL_WEBHOOK_SECRET', '--dry-run',
  ]);

  assert.equal(forbiddenSecret.status, 2, 'fal --secret-env must be rejected with exit 2.');
  assert.equal(existsSync(join(tempRoot, 'preview-fal-forbidden')), false);

  const wrongArm = invokeResult([
    'init', 'webhook', '--provider', 'vercel', '--framework', 'express', '--out', 'preview-vercel-wrong-arm',
    '--public-key-env', 'CUSTOM_FAL_PUBLIC_KEYS', '--dry-run',
  ]);

  assert.equal(wrongArm.status, 2, 'HMAC provider --public-key-env must be rejected with exit 2.');
  assert.equal(existsSync(join(tempRoot, 'preview-vercel-wrong-arm')), false);

  // The packed declarations must expose the exact 21-provider union and reject
  // mixing the HMAC and asymmetric credential arms. This compiles against the
  // installed node_modules tree, not the workspace sources.
  const tsc = join(root, 'node_modules', 'typescript', 'bin', 'tsc');
  assert(existsSync(tsc), 'TypeScript compiler is missing; run npm install in the workspace.');
  const typeProbe = join(tempRoot, 'installed-types-probe.ts');
  await writeFile(typeProbe, `
import {
  createVerifier,
  verify,
  verifyRequest,
  HooklatchError,
  type Provider,
  type VerifyOptions,
} from 'hooklatch';
import { diagnose } from 'hooklatch/diagnostics';

const providers: readonly Provider[] = [
  'stripe', 'github', 'shopify', 'standard-webhooks', 'clerk', 'svix',
  'razorpay', 'paddle', 'lemon-squeezy', 'dodo-payments', 'gitlab',
  'replicate', 'workos', 'sentry', 'doppler', 'sanity', 'grafana',
  'polar', 'linear', 'vercel', 'fal',
];

const hmac: VerifyOptions = { provider: 'vercel', secrets: ['synthetic-vercel-secret'] };
const asymmetric: VerifyOptions = { provider: 'fal', publicKeys: [new Uint8Array(32)], expectedUserId: 'user_synthetic' };

// @ts-expect-error fal must not carry shared HMAC secrets
const badFalSecrets: VerifyOptions = { provider: 'fal', publicKeys: [new Uint8Array(32)], expectedUserId: 'user_synthetic', secrets: ['synthetic'] };
// @ts-expect-error fal requires expectedUserId
const badFalMissingUser: VerifyOptions = { provider: 'fal', publicKeys: [new Uint8Array(32)] };
// @ts-expect-error vercel must not carry public keys
const badVercelKeys: VerifyOptions = { provider: 'vercel', secrets: ['synthetic'], publicKeys: [new Uint8Array(32)] };

void providers;
void hmac;
void asymmetric;
void badFalSecrets;
void badFalMissingUser;
void badVercelKeys;
void createVerifier(hmac);
void createVerifier(asymmetric);
void verify;
void verifyRequest;
void HooklatchError;
void diagnose;
`);
  execFileSync(process.execPath, [
    tsc, '--noEmit', '--strict', '--target', 'ES2022', '--module', 'ESNext',
    '--moduleResolution', 'Bundler', '--lib', 'ES2022,DOM', '--skipLibCheck', typeProbe,
  ], { cwd: tempRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });

  console.log('PASS: installed diagnostics, CLI credential arms and packed public types work without optional frameworks.');
} finally {
  const checked = resolve(tempRoot);
  assert(checked.startsWith(resolve(tmpdir()) + sep) && checked !== resolve(tmpdir()));
  await rm(checked, { recursive: true, force: true });
}
