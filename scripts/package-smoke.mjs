import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
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

  providerFixtures.push({ provider, cases });
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
        const options = { ...fixture.options, provider, now: () => fixture.options.now };
        const input = { rawBody, headers };
        const label = provider + ':' + fixture.id;

        const assertResult = (result, webTransport) => {
          assert.equal(result.ok, fixture.expected.ok, label);
          assert.equal(result.provider, provider, label);

          if (!result.ok) {
            assert.equal(result.reason, fixture.expected.reason, label);
            const failureDiagnostic = diagnose(result, { verbose: true });
            assert.equal(failureDiagnostic.provider, provider);
            assert.equal(failureDiagnostic.code, fixture.expected.reason);
            assert(failureDiagnostic.detail.expectedHeaders.length > 0);
            return;
          }

          const resolved = resolveIdentity(provider, fixture.expected.identity, headers, webTransport);
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
