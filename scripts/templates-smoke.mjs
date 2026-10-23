/**
 * Generated CLI qualification: every handler must be real, complete,
 * deterministic and semantically typechecked against the packed package and
 * the pinned framework/type trees from this checkout. Run AFTER npm run build:
 *
 *   node scripts/templates-smoke.mjs
 *
 * The generation set is derived from the built registry
 * (`dist/providers/index.js` `SUPPORTED_PROVIDERS`), so registering a provider
 * extends the matrix automatically. The Phase 9 target is 21 providers; at the
 * accepted 19-provider base readiness exits 3 (BLOCKED) before any temp
 * allocation, packing or generation. Only a registry that really contains the
 * reviewed vercel/fal tail reports 21 x 4 = 84 primary handlers.
 *
 * The expected credential table is exhaustive for the 21-provider target:
 * twenty HMAC secret-env names (the accepted 19 plus Vercel) and fal's distinct
 * public-key/expected-user arm. fal never receives a secret placeholder, and
 * the generated decoder is exercised with valid and malformed runtime env
 * values. Names whose provider the CLI does not register never reach generation.
 *
 * Grafana's primary row is generated with an explicit body-mode configuration and
 * must carry it into the emitted options; the optional configured-variant block
 * adds timestamped custom headers and Polar legacy mode. Vercel and fal, like the
 * existing providers, stay config-free.
 *
 * The script is standalone (no npm_execpath requirement). npm pack/install use
 * offline mode on the local tarball. Repository src and examples are never
 * imported as a verification fallback.
 */

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/**
 * Expected default secret env per HMAC provider, exhaustive for the 21-provider
 * target minus fal. `generate` is driven by the built registry, so names for
 * providers the CLI does not register never reach generation here.
 */
const EXPECTED_SECRET_ENV = {
  stripe: 'STRIPE_WEBHOOK_SECRET',
  github: 'GITHUB_WEBHOOK_SECRET',
  shopify: 'SHOPIFY_WEBHOOK_SECRET',
  'standard-webhooks': 'STANDARD_WEBHOOKS_SECRET',
  clerk: 'CLERK_WEBHOOK_SIGNING_SECRET',
  svix: 'SVIX_WEBHOOK_SECRET',
  razorpay: 'RAZORPAY_WEBHOOK_SECRET',
  paddle: 'PADDLE_WEBHOOK_SECRET',
  'lemon-squeezy': 'LEMON_SQUEEZY_WEBHOOK_SECRET',
  'dodo-payments': 'DODO_WEBHOOK_SECRET',
  gitlab: 'GITLAB_WEBHOOK_SECRET',
  replicate: 'REPLICATE_WEBHOOK_SECRET',
  workos: 'WORKOS_WEBHOOK_SECRET',
  sentry: 'SENTRY_WEBHOOK_SECRET',
  doppler: 'DOPPLER_WEBHOOK_SECRET',
  sanity: 'SANITY_WEBHOOK_SECRET',
  grafana: 'GRAFANA_WEBHOOK_SECRET',
  polar: 'POLAR_WEBHOOK_SECRET',
  linear: 'LINEAR_WEBHOOK_SECRET',
  vercel: 'VERCEL_WEBHOOK_SECRET',
};

const FAL_CREDENTIAL = {
  kind: 'fal',
  publicKeyEnv: 'FAL_WEBHOOK_PUBLIC_KEYS',
  expectedUserEnv: 'FAL_WEBHOOK_USER_ID',
};

/**
 * Exact 21-provider target order: the accepted nineteen-provider prefix in
 * contract order followed by vercel and fal. Kept explicit so an accidental
 * insertion in the middle cannot pass as an extension.
 */
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

const EXIT_PASS = 0;
const EXIT_NOT_READY = 3;
const TARGET_PROVIDERS = 21;
const EXISTING_PROVIDER_COUNT = 19;
const NEW_PROVIDERS = ['vercel', 'fal'];
const FAL_PUBLIC_KEY_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/** Providers whose CLI configuration is required/forwarded by this contract. */
const CONFIGURED_PROVIDERS = ['grafana', 'polar'];

/**
 * Primary generation recipe per configured provider. `flags` are appended to the
 * installed CLI invocation; `required`/`forbidden` are asserted against the
 * emitted source so a dropped configuration flag fails here.
 */
const PRIMARY_CONFIGURATION = {
  grafana: {
    flags: ['--grafana-mode', 'body'],
    requiresProviderOptions: true,
    required: [/providerOptions\s*:\s*\{/, /mode\s*:\s*['"]body['"]/],
    forbidden: [/timestampHeader\s*:/],
  },
  polar: {
    flags: [],
    requiresProviderOptions: false,
    required: [],
    forbidden: [/secretMode\s*:\s*['"]legacy['"]/],
    // Omitting the mode is the current default; an explicit mode must be current.
    modeForwarded: /secretMode\s*:\s*['"]current['"]/,
  },
};

/**
 * Configured variants: only generated for configured providers the built registry
 * actually exposes, because the installed CLI rejects a provider it has not
 * registered. A hostile-but-valid RFC9110 token is used to prove safe literal
 * serialization of an apostrophe-class header name without executable source.
 */
const CONFIGURED_VARIANTS = {
  grafana: {
    flags: ['--grafana-mode', 'timestamped', '--signature-header', 'x-acme`sig', '--timestamp-header', 'x-acme-timestamp'],
    required: [
      /providerOptions\s*:\s*\{/,
      /mode\s*:\s*['"]timestamped['"]/,
      /signatureHeader\s*:\s*['"]x-acme`sig['"]/,
      /timestampHeader\s*:\s*['"]x-acme-timestamp['"]/,
    ],
    forbidden: [/mode\s*:\s*['"]body['"]/],
  },
  polar: {
    flags: ['--polar-secret-mode', 'legacy'],
    required: [/providerOptions\s*:/, /secretMode\s*:\s*['"]legacy['"]/],
    forbidden: [/secretMode\s*:\s*['"]current['"]/],
  },
};

const FRAMEWORKS = ['express', 'nextjs', 'hono', 'cloudflare'];

const BODY_LIMIT = 1237;

function fail(message) {
  throw new Error(message);
}

/* Normalizes child-process failures into a labeled, nonempty diagnostic. */
function invoke(argv, cwd, label) {
  try {
    return execFileSync(process.execPath, argv, { cwd, encoding: 'utf8' });
  } catch (error) {
    const detail = [error.stdout, error.stderr].flatMap((part) => (String(part).trim().length > 0 ? [String(part)] : [])).join('\n');
    const enriched = new Error(`${label} failed with status ${error.status}${detail.length > 0 ? `:\n${detail}` : ''}`);

    enriched.exitStatus = error.status;
    throw enriched;
  }
}

/** Load the built internal registry; no public export is added or assumed. */
async function loadRegistryProviders() {
  const registryPath = join(root, 'dist', 'providers', 'index.js');
  const module = await import(pathToFileURL(registryPath).href);
  const providers = module.SUPPORTED_PROVIDERS;

  assert(Array.isArray(providers) && providers.length > 0,
    'The built registry did not expose a nonempty SUPPORTED_PROVIDERS array.');

  return [...providers];
}

function requireBuildArtifacts() {
  for (const artifact of [join('dist', 'index.js'), join('dist', 'cli', 'index.js'), join('dist', 'providers', 'index.js')]) {
    if (!existsSync(join(root, artifact))) {
      fail(`Built package artifact is missing: ${artifact}. Run npm run build before node scripts/templates-smoke.mjs.`);
    }
  }

  if (!existsSync(join(root, 'node_modules', 'typescript', 'lib', 'tsc.js'))) {
    fail('The pinned TypeScript toolchain is missing from this checkout; restore the prepared dependency snapshot.');
  }
}

/**
 * This harness's own expectation tables must be exhaustive before a registry
 * decision can be trusted. A missing vercel/fal env/order entry is a harness
 * defect, not acceptable success and not an upstream BLOCKED state.
 */
function assertExpectationCoverage() {
  assert.deepEqual(FRAMEWORKS, ['express', 'nextjs', 'hono', 'cloudflare'],
    'Template qualification must cover exactly the four supported frameworks.');
  assert.equal(EXPECTED_PROVIDER_ORDER.length, TARGET_PROVIDERS,
    `The expected provider order must contain exactly ${TARGET_PROVIDERS} providers.`);
  assert.equal(new Set(EXPECTED_PROVIDER_ORDER).size, TARGET_PROVIDERS,
    'The expected provider order must not contain duplicate IDs.');
  assert.deepEqual(EXPECTED_PROVIDER_ORDER.slice(0, EXISTING_PROVIDER_COUNT), [
    'stripe', 'github', 'shopify', 'standard-webhooks', 'clerk', 'svix',
    'razorpay', 'paddle', 'lemon-squeezy', 'dodo-payments', 'gitlab',
    'replicate', 'workos', 'sentry', 'doppler', 'sanity', 'grafana', 'polar', 'linear',
  ], 'The accepted nineteen-provider prefix must remain unchanged and in order.');
  assert.deepEqual(EXPECTED_PROVIDER_ORDER.slice(EXISTING_PROVIDER_COUNT), NEW_PROVIDERS,
    'The Phase 9 tail must be exactly vercel then fal.');
  assert.deepEqual(Object.keys(EXPECTED_SECRET_ENV), EXPECTED_PROVIDER_ORDER.filter((provider) => provider !== 'fal'),
    'The secret-env expectation keys must exactly match the 21-provider order minus fal.');
  assert.equal(Object.hasOwn(EXPECTED_SECRET_ENV, 'fal'), false,
    'fal must never have a secret-env expectation.');
  assert.equal(EXPECTED_SECRET_ENV.vercel, 'VERCEL_WEBHOOK_SECRET',
    'The Vercel secret-env expectation must be VERCEL_WEBHOOK_SECRET.');
  assert.deepEqual(FAL_CREDENTIAL, {
    kind: 'fal',
    publicKeyEnv: 'FAL_WEBHOOK_PUBLIC_KEYS',
    expectedUserEnv: 'FAL_WEBHOOK_USER_ID',
  }, 'The fal credential env defaults must match the frozen contract.');

  for (const provider of [...NEW_PROVIDERS, 'linear']) {
    assert.equal(Object.hasOwn(PRIMARY_CONFIGURATION, provider), false,
      `${provider} must remain config-free; remove any primary configuration recipe.`);
    assert.equal(Object.hasOwn(CONFIGURED_VARIANTS, provider), false,
      `${provider} must not define a configured variant.`);
  }

  for (const provider of CONFIGURED_PROVIDERS) {
    assert.equal(Object.hasOwn(EXPECTED_SECRET_ENV, provider), true,
      `Configured provider ${provider} is missing from the secret-env expectation table.`);
    assert.equal(Object.hasOwn(PRIMARY_CONFIGURATION, provider), true,
      `Configured provider ${provider} has no primary generation recipe.`);
    assert.equal(Object.hasOwn(CONFIGURED_VARIANTS, provider), true,
      `Configured provider ${provider} has no configured variant recipe.`);
  }
}

/** Pure readiness decision for the built registry (the 19-provider base blocks). */
function decideReadiness(providers) {
  if (!Array.isArray(providers) || providers.length === 0) {
    return { ready: false, reason: 'The built registry did not expose a nonempty SUPPORTED_PROVIDERS array.' };
  }

  if (providers.length !== TARGET_PROVIDERS) {
    return {
      ready: false,
      reason: `Registry has ${providers.length} providers; the 21-provider template matrix requires exactly ${TARGET_PROVIDERS} (accepted ${EXISTING_PROVIDER_COUNT}-provider prefix plus vercel/fal).`,
    };
  }

  if (new Set(providers).size !== TARGET_PROVIDERS) {
    return { ready: false, reason: 'Registry provider IDs are not unique.' };
  }

  for (let index = 0; index < TARGET_PROVIDERS; index += 1) {
    if (providers[index] !== EXPECTED_PROVIDER_ORDER[index]) {
      return {
        ready: false,
        reason: `Registry provider #${index} is ${JSON.stringify(providers[index])}; expected ${JSON.stringify(EXPECTED_PROVIDER_ORDER[index])} (accepted ${EXISTING_PROVIDER_COUNT}-provider prefix plus vercel/fal).`,
      };
    }
  }

  return { ready: true, reason: '' };
}

/**
 * Built-CLI prerequisite. The fal flags must be advertised before a temp
 * consumer is allocated; a 19-provider registry already blocks before this.
 */
function decideCliReadiness() {
  const cli = join(root, 'dist', 'cli', 'index.js');

  if (!existsSync(cli)) return { ready: false, reason: 'Built CLI is missing: dist/cli/index.js.' };

  try {
    const help = invoke([cli, '--help'], root, 'built CLI help');
    const missing = ['--secret-env', '--public-key-env', '--expected-user-env'].filter((flag) => !help.includes(flag));

    return missing.length === 0
      ? { ready: true, reason: '' }
      : { ready: false, reason: `Built CLI help is missing credential flag(s): ${missing.join(', ')}.` };
  } catch (error) {
    return { ready: false, reason: error.message };
  }
}

function locateNpmCli() {
  const candidates = [];

  if (process.env.npm_execpath) candidates.push(process.env.npm_execpath);

  candidates.push(
    join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    join(dirname(process.execPath), '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
  );

  const found = candidates.find((candidate) => existsSync(candidate));

  if (!found) {
    fail('npm CLI is unavailable: neither npm_execpath nor the node install tree provide npm-cli.js.');
  }

  return found;
}

function installedCliPath(consumerRoot) {
  const cli = join(consumerRoot, 'node_modules', 'hooklatch', 'dist', 'cli', 'index.js');

  if (!existsSync(cli)) {
    fail('The installed packed package does not expose dist/cli/index.js; inspect the npm tarball contents.');
  }

  return cli;
}

function linkFixedDependency(localName, consumerRoot) {
  const target = resolve(join(root, 'node_modules', localName));

  if (!existsSync(target)) {
    fail(`Pinned dependency tree is missing from this checkout: ${localName} (the repository node_modules stays read-only).`);
  }

  const linkPath = join(consumerRoot, 'node_modules', localName);

  mkdirSync(dirname(linkPath), { recursive: true });
  symlinkSync(target, linkPath, process.platform === 'win32' ? 'junction' : 'dir');
}

function expectedFileName(provider, framework) {
  if (framework === 'nextjs') return 'route.ts';

  if (framework === 'cloudflare') return `${provider}.cloudflare.ts`;

  return `${provider}.${framework}.ts`;
}

function requirePattern(content, pattern, label) {
  if (!pattern.test(content)) fail(`${label} is missing ${pattern}.`);
}

function forbidPattern(content, pattern, label) {
  if (pattern.test(content)) fail(`${label} must not contain ${pattern}.`);
}

/**
 * Assert that the generated options carry exactly the configuration the recipe
 * requested, and that existing providers remain configuration-free.
 */
function expectProviderConfiguration(provider, framework, content) {
  const label = `Generated ${framework} handler for ${provider}`;
  const recipe = PRIMARY_CONFIGURATION[provider];

  if (recipe === undefined) {
    if (content.includes('providerOptions')) {
      fail(`${label} must stay config-free; providerOptions is not allowed for existing providers.`);
    }

    return;
  }

  const hasOptions = /providerOptions\s*:/.test(content);

  if (recipe.requiresProviderOptions && !hasOptions) {
    fail(`${label} is missing the required providerOptions configuration.`);
  }

  if (!recipe.requiresProviderOptions && recipe.modeForwarded !== undefined && /secretMode\s*:/.test(content)) {
    requirePattern(content, recipe.modeForwarded, label);
  }

  for (const pattern of recipe.required) requirePattern(content, pattern, label);

  for (const pattern of recipe.forbidden) forbidPattern(content, pattern, label);
}

function credentialFor(provider) {
  if (provider === 'fal') return FAL_CREDENTIAL;

  const secretEnv = EXPECTED_SECRET_ENV[provider];

  if (secretEnv === undefined) fail(`No HMAC secret-env expectation for ${provider}.`);

  return { kind: 'hmac', secretEnv };
}

function expectContentMarkers(provider, framework, credential, content) {
  for (const marker of [`provider: '${provider}'`, `maxBodyBytes: ${BODY_LIMIT}`]) {
    if (!content.includes(marker)) {
      fail(`Generated ${framework} handler for ${provider} is missing: ${marker}`);
    }
  }

  expectProviderConfiguration(provider, framework, content);

  if (credential.kind === 'fal') {
    for (const marker of ['publicKeys', 'expectedUserId', 'atob(']) {
      if (!content.includes(marker)) {
        fail(`Generated ${framework} fal handler is missing: ${marker}`);
      }
    }

    forbidPattern(content, /\bsecrets?\s*:/, `Generated ${framework} fal handler`);
    forbidPattern(content, /\b(?:process\.env|env)\.FAL_WEBHOOK_SECRET\b/, `Generated ${framework} fal handler`);
    forbidPattern(content, /\bBuffer\s*\./, `Generated ${framework} fal handler`);
    forbidPattern(content, /\brequire\s*\(/, `Generated ${framework} fal handler`);

    if (framework === 'cloudflare') {
      for (const marker of [
        `from 'hooklatch/cloudflare'`,
        `${credential.publicKeyEnv}: string`,
        `${credential.expectedUserEnv}: string`,
        `env.${credential.publicKeyEnv}`,
        `env.${credential.expectedUserEnv}`,
      ]) {
        if (!content.includes(marker)) {
          fail(`Generated cloudflare fal handler is missing: ${marker}`);
        }
      }

      return;
    }

    const sharedMarkers = [
      `from 'hooklatch/${framework}'`,
      `process.env.${credential.publicKeyEnv}`,
      `process.env.${credential.expectedUserEnv}`,
    ];

    if (framework === 'hono') sharedMarkers.push(`from 'hono'`);

    for (const marker of sharedMarkers) {
      if (!content.includes(marker)) {
        fail(`Generated ${framework} fal handler is missing: ${marker}`);
      }
    }

    return;
  }

  forbidPattern(content, /\bpublicKeys\s*:/, `Generated ${framework} ${provider} handler`);
  forbidPattern(content, /\bexpectedUserId\s*:/, `Generated ${framework} ${provider} handler`);

  if (framework === 'cloudflare') {
    for (const marker of [`from 'hooklatch/cloudflare'`, `${credential.secretEnv}: string`, `env.${credential.secretEnv}`]) {
      if (!content.includes(marker)) {
        fail(`Generated cloudflare handler for ${provider} is missing: ${marker}`);
      }
    }

    return;
  }

  const sharedMarkers = [`from 'hooklatch/${framework}'`, `process.env.${credential.secretEnv}!`];

  if (framework === 'hono') sharedMarkers.push(`from 'hono'`);

  for (const marker of sharedMarkers) {
    if (!content.includes(marker)) {
      fail(`Generated ${framework} handler for ${provider} is missing: ${marker}`);
    }
  }
}

/* Every combination directory must hold exactly the generated target file. */
function assertCompletedDir(directory, fileName, label) {
  const entries = readdirSync(directory);

  if (entries.length !== 1 || entries[0] !== fileName) {
    fail(`${label} produced [${entries.join(', ')}] instead of exactly [${fileName}].`);
  }
}

function generationArgv(cli, provider, framework, credential, relativeOut, extraFlags = []) {
  const credentialFlags = credential.kind === 'fal'
    ? ['--public-key-env', credential.publicKeyEnv, '--expected-user-env', credential.expectedUserEnv]
    : ['--secret-env', credential.secretEnv];

  return [
    cli,
    'init', 'webhook',
    '--provider', provider,
    '--framework', framework,
    '--out', relativeOut,
    ...credentialFlags,
    '--body-limit', String(BODY_LIMIT),
    ...extraFlags,
  ];
}

/* Compiler options mirror the repo's own checker (skipLibCheck parity). */
function typecheckGeneratedFile(file, consumerRoot, label) {
  const argv = [
    join(root, 'node_modules', 'typescript', 'lib', 'tsc.js'),
    '--noEmit',
    '--strict',
    '--target', 'es2022',
    '--module', 'nodenext',
    '--moduleResolution', 'nodenext',
    '--lib', 'es2022,dom,dom.iterable',
    '--types', 'node',
    '--esModuleInterop',
    '--skipLibCheck',
    '--exactOptionalPropertyTypes',
    '--noUncheckedIndexedAccess',
    '--verbatimModuleSyntax',
    file,
  ];

  invoke(argv, consumerRoot, `semantic typecheck of ${label}`);
}

function noncanonicalFalKey(key) {
  const last = key[key.length - 1];
  const index = FAL_PUBLIC_KEY_ALPHABET.indexOf(last);

  assert(index >= 0, 'Synthetic fal key ended with a character outside the Base64url alphabet.');

  const variant = `${key.slice(0, -1)}${FAL_PUBLIC_KEY_ALPHABET[index ^ 1]}`;

  assert.deepEqual([...Buffer.from(variant, 'base64url')], [...Buffer.from(key, 'base64url')],
    'The noncanonical control must decode to the same 32 bytes.');
  assert.notEqual(variant, key, 'The noncanonical control must differ from the canonical string.');

  return variant;
}

/**
 * Semantic check of the generated runtime decoder, not a substring check. It
 * bundles the generated Next.js fal handler, imports it with a synthetic valid
 * Ed25519 key, drives a real signed Request, then proves padded/whitespace/
 * wrong-length/noncanonical/17-key/blank/missing-account env values fail
 * closed without echoing the supplied environment value.
 */
async function assertFalDecoderSemantics(consumerRoot, sourcePath) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' });

  assert.equal(jwk.kty, 'OKP', 'Synthetic Ed25519 key must export as an OKP JWK.');
  assert.equal(jwk.crv, 'Ed25519', 'Synthetic Ed25519 key must export curve Ed25519.');

  if (Object.prototype.toString.call(jwk.x) !== '[object String]' || !/^[A-Za-z0-9_-]{43}$/.test(jwk.x)) {
    fail('Synthetic Ed25519 public key did not export as a 43-character Base64url string.');
  }

  const publicKeyText = jwk.x;
  const userId = 'user_templates_synthetic_fal';
  const requestId = 'req_templates_synthetic_fal';
  const timestamp = Math.floor(Date.now() / 1000);
  const body = Buffer.from('{"synthetic":"templates-fal-decoder"}');
  const digest = createHash('sha256').update(body).digest('hex');
  const signedContent = Buffer.from(`${requestId}\n${userId}\n${timestamp}\n${digest}`, 'utf8');
  const signature = sign(null, signedContent, privateKey).toString('hex');

  const requestHeaders = {
    'x-fal-webhook-signature': signature,
    'x-fal-webhook-request-id': requestId,
    'x-fal-webhook-user-id': userId,
    'x-fal-webhook-timestamp': String(timestamp),
  };

  const bundle = await build({
    entryPoints: [sourcePath],
    absWorkingDir: consumerRoot,
    bundle: true,
    write: false,
    platform: 'node',
    format: 'esm',
    target: 'node22',
    logLevel: 'silent',
  });

  assert.equal(bundle.outputFiles.length, 1, 'Generated fal handler bundling did not produce one module.');

  const runtimeFile = join(consumerRoot, 'fal-runtime-decoder.mjs');

  writeFileSync(runtimeFile, bundle.outputFiles[0].text);

  const runtimeUrl = pathToFileURL(runtimeFile).href;
  const savedPublicKeys = process.env.FAL_WEBHOOK_PUBLIC_KEYS;
  const savedUserId = process.env.FAL_WEBHOOK_USER_ID;

  const setEnv = (nextPublicKeys, nextUserId) => {
    if (nextPublicKeys === undefined) delete process.env.FAL_WEBHOOK_PUBLIC_KEYS;
    else process.env.FAL_WEBHOOK_PUBLIC_KEYS = nextPublicKeys;

    if (nextUserId === undefined) delete process.env.FAL_WEBHOOK_USER_ID;
    else process.env.FAL_WEBHOOK_USER_ID = nextUserId;
  };

  const requestFor = () => new Request('https://example.test/webhook', {
    method: 'POST',
    headers: requestHeaders,
    body: new Uint8Array(body),
  });

  const attempt = async (label) => {
    try {
      const module = await import(`${runtimeUrl}?case=${encodeURIComponent(label)}`);
      const postKind = Object.prototype.toString.call(module.POST);

      if (postKind !== '[object Function]' && postKind !== '[object AsyncFunction]') {
        return { failure: new Error('Generated fal handler did not export POST.'), status: null, body: '' };
      }

      const response = await module.POST(requestFor());

      return { failure: null, status: response.status, body: await response.text() };
    } catch (error) {
      return { failure: error, status: null, body: '' };
    }
  };

  try {
    setEnv(publicKeyText, userId);

    const valid = await attempt('valid');

    assert.equal(valid.failure, null, `Valid fal runtime env failed to load: ${valid.failure?.message ?? ''}`);
    assert.equal(valid.status, 200, `Valid signed fal Request returned HTTP ${valid.status}.`);

    const invalidCases = [
      { label: 'padded', publicKeys: `${publicKeyText}=`, userId },
      { label: 'noncanonical', publicKeys: noncanonicalFalKey(publicKeyText), userId },
      { label: '31-byte', publicKeys: Buffer.alloc(31, 1).toString('base64url'), userId },
      { label: '33-byte', publicKeys: Buffer.alloc(33, 1).toString('base64url'), userId },
      { label: '17-keys', publicKeys: Array.from({ length: 17 }, () => publicKeyText).join(','), userId },
      { label: 'empty-entry', publicKeys: `,${publicKeyText}`, userId },
      { label: 'blank', publicKeys: '', userId },
      { label: 'missing-public', publicKeys: undefined, userId },
      { label: 'whitespace', publicKeys: `${publicKeyText} `, userId },
      { label: 'missing-user', publicKeys: publicKeyText, userId: undefined },
      { label: 'blank-user', publicKeys: publicKeyText, userId: '' },
      { label: 'comma-user', publicKeys: publicKeyText, userId: 'bad,user' },
      { label: 'space-user', publicKeys: publicKeyText, userId: 'bad user' },
    ];

    for (const invalid of invalidCases) {
      setEnv(invalid.publicKeys, invalid.userId);

      const outcome = await attempt(`invalid-${invalid.label}`);

      const failed = outcome.failure !== null
        || (outcome.status !== null && outcome.status >= 400 && outcome.status < 600);

      assert(failed, `Generated fal decoder accepted invalid ${invalid.label} runtime env (HTTP ${outcome.status}).`);

      const detail = `${outcome.failure?.message ?? ''} ${outcome.body}`;

      for (const value of [invalid.publicKeys, invalid.userId]) {
        if (value === undefined || value.length === 0) continue;
        assert(!detail.includes(value), `Generated fal decoder echoed the invalid ${invalid.label} env value.`);
      }
    }
  } finally {
    setEnv(savedPublicKeys, savedUserId);
  }
}

async function main() {
  assertExpectationCoverage();
  requireBuildArtifacts();

  const providers = await loadRegistryProviders();
  const readiness = decideReadiness(providers);

  if (!readiness.ready) {
    console.error(`BLOCKED (exit ${EXIT_NOT_READY}): ${readiness.reason}`);
    console.error('No temp root was allocated and no package was installed or generated.');

    return EXIT_NOT_READY;
  }

  const cliReadiness = decideCliReadiness();

  if (!cliReadiness.ready) {
    console.error(`BLOCKED (exit ${EXIT_NOT_READY}): ${cliReadiness.reason}`);
    console.error('No temp root was allocated and no package was installed or generated.');

    return EXIT_NOT_READY;
  }

  const npmCli = locateNpmCli();
  const tempRoot = await mkdtemp(join(tmpdir(), 'hooklatch-templates-'));
  const consumerRoot = join(tempRoot, 'consumer');

  try {
    mkdirSync(consumerRoot);

    // The consumer pins an ESM module system; the tarball below carries the
    // entire hooklatch surface, so no repository code is imported anywhere.
    const consumerManifest = {
      name: 'hooklatch-template-consumer',
      version: '0.0.0',
      private: true,
      type: 'module',
    };

    writeFileSync(join(consumerRoot, 'package.json'), `${JSON.stringify(consumerManifest, null, 2)}\n`);

    const packed = JSON.parse(invoke([npmCli, 'pack', '--json', '--offline', '--ignore-scripts', '--pack-destination', tempRoot], root, 'npm pack'));
    const tarballPath = join(tempRoot, packed[0].filename);

    if (!existsSync(tarballPath)) fail('npm pack did not produce the expected archive.');

    invoke(
      [npmCli, 'install', tarballPath, '--no-save', '--ignore-scripts', '--offline', '--no-audit', '--no-fund'],
      consumerRoot,
      'offline npm install of the packed package',
    );

    const cli = installedCliPath(consumerRoot);

    for (const name of ['express', 'hono', '@types/express', '@types/node']) linkFixedDependency(name, consumerRoot);

    let primaryCount = 0;

    for (const provider of providers) {
      const credential = credentialFor(provider);
      const primaryFlags = PRIMARY_CONFIGURATION[provider]?.flags ?? [];

      for (const framework of FRAMEWORKS) {
        const label = `${provider}/${framework}`;
        const relativeOut = join('gen', provider, framework);
        const relativeOutCopy = join('gen2', provider, framework);
        const firstDir = join(consumerRoot, relativeOut);
        const secondDir = join(consumerRoot, relativeOutCopy);

        const generationLabel = `hooklatch init webhook (${label})`;

        invoke(generationArgv(cli, provider, framework, credential, relativeOut, primaryFlags), consumerRoot, generationLabel);

        assertCompletedDir(firstDir, expectedFileName(provider, framework), `Generation (${label})`);

        const firstPath = join(firstDir, expectedFileName(provider, framework));
        const content = readFileSync(firstPath, 'utf8');

        expectContentMarkers(provider, framework, credential, content);

        invoke(generationArgv(cli, provider, framework, credential, relativeOutCopy, primaryFlags), consumerRoot, `deterministic regeneration (${label})`);

        assertCompletedDir(secondDir, expectedFileName(provider, framework), `Regeneration (${label})`);

        if (!readFileSync(firstPath).equals(readFileSync(join(secondDir, expectedFileName(provider, framework))))) {
          fail(`Regenerated bytes differ between runs for ${label}.`);
        }

        // Independent compiler program: one NodeNext child per generated file.
        typecheckGeneratedFile(firstPath, consumerRoot, label);
        primaryCount += 1;
      }
    }

    if (primaryCount !== TARGET_PROVIDERS * FRAMEWORKS.length) {
      fail(`Primary matrix is reduced: ${primaryCount} handlers instead of ${TARGET_PROVIDERS * FRAMEWORKS.length}.`);
    }

    const falNextPath = join(consumerRoot, 'gen', 'fal', 'nextjs', 'route.ts');

    if (!existsSync(falNextPath)) fail('The fal Next.js primary handler is missing; decoder semantics cannot be checked.');

    await assertFalDecoderSemantics(consumerRoot, falNextPath);

    // Configured variants exercise explicit non-default forwarding. Readiness
    // requires both configured providers, so a missing variant recipe is a real
    // matrix failure rather than an acceptable partial run.
    const configuredRegistered = providers.filter((provider) => Object.hasOwn(CONFIGURED_VARIANTS, provider));

    if (configuredRegistered.length !== CONFIGURED_PROVIDERS.length) {
      fail(`Configured variant providers are reduced: [${configuredRegistered.join(', ')}] instead of [${CONFIGURED_PROVIDERS.join(', ')}].`);
    }

    let variantCount = 0;

    for (const provider of configuredRegistered) {
      const credential = credentialFor(provider);
      const variant = CONFIGURED_VARIANTS[provider];

      for (const framework of FRAMEWORKS) {
        const label = `${provider}-configured/${framework}`;
        const relativeOut = join('gen-configured', provider, framework);
        const outDir = join(consumerRoot, relativeOut);
        const contentLabel = `Configured ${framework} handler for ${provider}`;

        invoke(generationArgv(cli, provider, framework, credential, relativeOut, variant.flags), consumerRoot,
          `hooklatch init webhook configured (${label})`);
        assertCompletedDir(outDir, expectedFileName(provider, framework), `Configured generation (${label})`);

        const file = join(outDir, expectedFileName(provider, framework));
        const content = readFileSync(file, 'utf8');

        for (const pattern of variant.required) requirePattern(content, pattern, contentLabel);

        for (const pattern of variant.forbidden) forbidPattern(content, pattern, contentLabel);

        typecheckGeneratedFile(file, consumerRoot, label);
        variantCount += 1;
      }
    }

    if (variantCount !== CONFIGURED_PROVIDERS.length * FRAMEWORKS.length) {
      fail(`Configured variant matrix is reduced: ${variantCount} handlers instead of ${CONFIGURED_PROVIDERS.length * FRAMEWORKS.length}.`);
    }

    // The installed CLI must reject an unimplemented provider and write nothing.
    let invalidStatus;

    try {
      invoke([cli, 'init', 'webhook', '--provider', 'does-not-exist', '--framework', 'express', '--out', 'gen-invalid'], consumerRoot, 'invalid provider probe');

      invalidStatus = -1;
    } catch (error) {
      invalidStatus = error.exitStatus !== undefined ? error.exitStatus : -1;
    }

    if (invalidStatus !== 2) fail(`Installed CLI accepted an unknown provider (status ${invalidStatus}).`);

    if (existsSync(join(consumerRoot, 'gen-invalid'))) fail('Installed CLI wrote output for a rejected provider.');

    console.log(`PASS: ${primaryCount} primary generated handlers across ${providers.length} registered providers are complete, deterministic and semantically typechecked; ${variantCount} configured variants independently typechecked; fal runtime decoder accepted a signed Request and rejected malformed env values without echo.`);

    return EXIT_PASS;
  } finally {
    const checked = resolve(tempRoot);

    assert(checked.startsWith(resolve(tmpdir()) + sep) && checked !== resolve(tmpdir()));
    rmSync(checked, { recursive: true, force: true });
    assert(!existsSync(checked), 'Checked temp root must be removed on every outcome.');
  }
}

try {
  process.exitCode = await main();
} catch (error) {
  console.error(`FAIL: templates smoke (${error.message})`);
  process.exitCode = 1;
}
