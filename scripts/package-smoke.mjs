import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
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

  for (const key of Object.keys(options)) {
    assert(['secrets', 'now', 'toleranceSeconds', 'providerOptions'].includes(key),
      `${label}: unexpected options key ${JSON.stringify(key)}.`);
  }

  assert(Array.isArray(options.secrets) && options.secrets.length > 0, `${label}: options.secrets must be a nonempty array.`);

  for (const secret of options.secrets) requireKind(secret, 'String', `${label}: each secret`);

  // Fractional epoch seconds are legitimate existing freshness coverage.
  // Number.isFinite rejects non-number JSON kinds without a typeof branch.
  assert(Number.isFinite(options.now) && options.now >= 0,
    `${label}: options.now must be a fixed nonnegative finite epoch-second clock.`);

  if (options.toleranceSeconds !== undefined) {
    assert(Number.isSafeInteger(options.toleranceSeconds) && options.toleranceSeconds >= 0,
      `${label}: options.toleranceSeconds must be a nonnegative safe integer.`);
  }

  validateFixtureProviderOptions(provider, options.providerOptions, label);

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

  providerFixtures.push({ provider, cases });
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
  const paths = new Set([packageManifest.main, packageManifest.types]);

  for (const target of Object.values(packageManifest.exports ?? {})) {
    paths.add(target.types);
    paths.add(target.import);
  }

  for (const target of Object.values(packageManifest.bin ?? {})) paths.add(target);

  paths.delete(undefined);

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
    // key cannot leak through unnoticed, and providerOptions is forwarded only
    // when the fixture declares it (an own undefined is invalid publicly).
    const buildOptions = (provider, options) => {
      const built = { provider, secrets: options.secrets, now: () => options.now };

      if (options.toleranceSeconds !== undefined) built.toleranceSeconds = options.toleranceSeconds;
      if (options.providerOptions !== undefined) built.providerOptions = options.providerOptions;

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
        assertResult(await verifyRequest(new Request('https://example.test/hook', {
          method: 'POST', headers, body: rawBody,
        }), options), true);

        if (fixture.expected.ok) {
          const changed = new Uint8Array(rawBody.length + 1);
          changed.set(rawBody);
          changed[rawBody.length] = 33;
          const tampered = await verify({ ...input, rawBody: changed }, options);
          assert.equal(tampered.ok, false);
          assert.equal(tampered.reason, 'invalid-signature');
        }
      }

      console.log('PASS: packed ' + provider + ' corpus passes all three APIs, metadata, diagnostics and tamper rejection.');

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

    for (const name of ['express', 'hono']) {
      await assert.rejects(import(name), { code: 'ERR_MODULE_NOT_FOUND' });
    }
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
  assert(invoke(['--help']).includes('Usage: hooklatch'));
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
  ]) {
    const output = `preview-${provider}`;
    const content = invoke(['init', 'webhook', '--provider', provider, '--framework', 'express', '--out', output, '--dry-run']);
    assert(content.includes(`provider: '${provider}'`));
    assert(content.includes(`process.env.${secretEnv}!`));
    assert.equal(existsSync(join(tempRoot, output)), false);
  }

  console.log('PASS: installed diagnostics and CLI help/dry-run work without optional frameworks.');
} finally {
  const checked = resolve(tempRoot);
  assert(checked.startsWith(resolve(tmpdir()) + sep) && checked !== resolve(tmpdir()));
  await rm(checked, { recursive: true, force: true });
}
