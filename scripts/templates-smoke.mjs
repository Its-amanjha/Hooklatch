/**
 * Generated CLI qualification: every handler must be real, complete,
 * deterministic and semantically typechecked against the packed package and
 * the pinned framework/type trees from this checkout. Run AFTER npm run build:
 *
 *   node scripts/templates-smoke.mjs
 *
 * The generation set is derived from the built registry
 * (`dist/providers/index.js` `SUPPORTED_PROVIDERS`), so registering a provider
 * extends the matrix automatically. The Phase 8 Stage A target is 19 providers;
 * at the accepted 18-provider base readiness exits 3 (BLOCKED) before any temp
 * allocation, packing or generation. Only a registry that really contains
 * Linear reports 19 x 4 = 76 primary handlers. The expected secret-env table is
 * exhaustive for the 19-provider target (the accepted 18 plus
 * LINEAR_WEBHOOK_SECRET); names whose provider the CLI does not register never
 * reach generation.
 *
 * Grafana's primary row is generated with an explicit body-mode configuration and
 * must carry it into the emitted options; the optional configured-variant block
 * adds timestamped custom headers and Polar legacy mode. Linear, like the
 * existing providers, stays config-free.
 *
 * The script is standalone (no npm_execpath requirement). npm pack/install use
 * offline mode on the local tarball. Repository src and examples are never
 * imported as a verification fallback.
 */

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/**
 * Expected default secret env per provider, exhaustive for the 19-provider
 * target (the accepted 18-provider contract plus Linear). `generate` is driven by
 * the built registry, so names for providers the CLI does not register never
 * reach generation here.
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
};

/**
 * Exact 19-provider target order: the accepted 18-provider prefix in contract
 * order followed by Linear. Kept explicit so an accidental insertion in the
 * middle cannot pass as an extension.
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
];

const EXIT_PASS = 0;
const EXIT_NOT_READY = 3;
const TARGET_PROVIDERS = 19;
const EXISTING_PROVIDER_COUNT = 18;

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
 * decision can be trusted. A missing Linear env/order entry is a harness defect,
 * not acceptable success and not an upstream BLOCKED state.
 */
function assertExpectationCoverage() {
  assert.deepEqual(FRAMEWORKS, ['express', 'nextjs', 'hono', 'cloudflare'],
    'Template qualification must cover exactly the four supported frameworks.');
  assert.equal(EXPECTED_PROVIDER_ORDER.length, EXISTING_PROVIDER_COUNT + 1,
    `The expected provider order must append exactly one provider to the accepted ${EXISTING_PROVIDER_COUNT}.`);
  assert.equal(EXPECTED_PROVIDER_ORDER.length, TARGET_PROVIDERS,
    `The expected provider order must contain exactly ${TARGET_PROVIDERS} providers.`);
  assert.equal(new Set(EXPECTED_PROVIDER_ORDER).size, TARGET_PROVIDERS,
    'The expected provider order must not contain duplicate IDs.');
  assert.deepEqual(Object.keys(EXPECTED_SECRET_ENV), EXPECTED_PROVIDER_ORDER,
    'The secret-env expectation keys must exactly match the expected provider order.');
  assert.equal(EXPECTED_PROVIDER_ORDER[EXPECTED_PROVIDER_ORDER.length - 1], 'linear',
    'Linear must be appended after the accepted 18-provider prefix.');
  assert.equal(EXPECTED_SECRET_ENV.linear, 'LINEAR_WEBHOOK_SECRET',
    'The Linear secret-env expectation must be LINEAR_WEBHOOK_SECRET.');
  assert.equal(Object.hasOwn(PRIMARY_CONFIGURATION, 'linear'), false,
    'Linear must remain config-free; remove any primary configuration recipe.');
  assert.equal(Object.hasOwn(CONFIGURED_VARIANTS, 'linear'), false,
    'Linear must not define a configured variant.');

  for (const provider of CONFIGURED_PROVIDERS) {
    assert.equal(Object.hasOwn(EXPECTED_SECRET_ENV, provider), true,
      `Configured provider ${provider} is missing from the secret-env expectation table.`);
    assert.equal(Object.hasOwn(PRIMARY_CONFIGURATION, provider), true,
      `Configured provider ${provider} has no primary generation recipe.`);
    assert.equal(Object.hasOwn(CONFIGURED_VARIANTS, provider), true,
      `Configured provider ${provider} has no configured variant recipe.`);
  }
}

/** Pure readiness decision for the built registry (the 18-provider base blocks). */
function decideReadiness(providers) {
  if (!Array.isArray(providers) || providers.length === 0) {
    return { ready: false, reason: 'The built registry did not expose a nonempty SUPPORTED_PROVIDERS array.' };
  }

  if (providers.length !== TARGET_PROVIDERS) {
    return {
      ready: false,
      reason: `Registry has ${providers.length} providers; the 19-provider template matrix requires exactly ${TARGET_PROVIDERS} (accepted ${EXISTING_PROVIDER_COUNT}-provider prefix plus linear).`,
    };
  }

  if (new Set(providers).size !== TARGET_PROVIDERS) {
    return { ready: false, reason: 'Registry provider IDs are not unique.' };
  }

  for (let index = 0; index < TARGET_PROVIDERS; index += 1) {
    if (providers[index] !== EXPECTED_PROVIDER_ORDER[index]) {
      return {
        ready: false,
        reason: `Registry provider #${index} is ${JSON.stringify(providers[index])}; expected ${JSON.stringify(EXPECTED_PROVIDER_ORDER[index])} (accepted ${EXISTING_PROVIDER_COUNT}-provider prefix plus linear).`,
      };
    }
  }

  return { ready: true };
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

function expectContentMarkers(provider, framework, secretEnv, content) {
  for (const marker of [`provider: '${provider}'`, `maxBodyBytes: ${BODY_LIMIT}`]) {
    if (!content.includes(marker)) {
      fail(`Generated ${framework} handler for ${provider} is missing: ${marker}`);
    }
  }

  expectProviderConfiguration(provider, framework, content);

  if (framework === 'cloudflare') {
    for (const marker of [`from 'hooklatch/cloudflare'`, `${secretEnv}: string`, `env.${secretEnv}`]) {
      if (!content.includes(marker)) {
        fail(`Generated cloudflare handler for ${provider} is missing: ${marker}`);
      }
    }

    return;
  }

  const sharedMarkers = [`from 'hooklatch/${framework}'`, `process.env.${secretEnv}!`];

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

function generationArgv(cli, provider, framework, secretEnv, relativeOut, extraFlags = []) {
  return [
    cli,
    'init', 'webhook',
    '--provider', provider,
    '--framework', framework,
    '--out', relativeOut,
    '--secret-env', secretEnv,
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
      const secretEnv = EXPECTED_SECRET_ENV[provider];
      const primaryFlags = PRIMARY_CONFIGURATION[provider]?.flags ?? [];

      for (const framework of FRAMEWORKS) {
        const label = `${provider}/${framework}`;
        const relativeOut = join('gen', provider, framework);
        const relativeOutCopy = join('gen2', provider, framework);
        const firstDir = join(consumerRoot, relativeOut);
        const secondDir = join(consumerRoot, relativeOutCopy);

        const generationLabel = `hooklatch init webhook (${label})`;

        invoke(generationArgv(cli, provider, framework, secretEnv, relativeOut, primaryFlags), consumerRoot, generationLabel);

        assertCompletedDir(firstDir, expectedFileName(provider, framework), `Generation (${label})`);

        const firstPath = join(firstDir, expectedFileName(provider, framework));
        const content = readFileSync(firstPath, 'utf8');

        expectContentMarkers(provider, framework, secretEnv, content);

        invoke(generationArgv(cli, provider, framework, secretEnv, relativeOutCopy, primaryFlags), consumerRoot, `deterministic regeneration (${label})`);

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

    // Configured variants exercise explicit non-default forwarding. Readiness
    // requires both configured providers, so a missing variant recipe is a real
    // matrix failure rather than an acceptable partial run.
    const configuredRegistered = providers.filter((provider) => Object.hasOwn(CONFIGURED_VARIANTS, provider));

    if (configuredRegistered.length !== CONFIGURED_PROVIDERS.length) {
      fail(`Configured variant providers are reduced: [${configuredRegistered.join(', ')}] instead of [${CONFIGURED_PROVIDERS.join(', ')}].`);
    }

    let variantCount = 0;

    for (const provider of configuredRegistered) {
      const secretEnv = EXPECTED_SECRET_ENV[provider];
      const variant = CONFIGURED_VARIANTS[provider];

      for (const framework of FRAMEWORKS) {
        const label = `${provider}-configured/${framework}`;
        const relativeOut = join('gen-configured', provider, framework);
        const outDir = join(consumerRoot, relativeOut);
        const contentLabel = `Configured ${framework} handler for ${provider}`;

        invoke(generationArgv(cli, provider, framework, secretEnv, relativeOut, variant.flags), consumerRoot,
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

    console.log(`PASS: ${primaryCount} primary generated handlers across ${providers.length} registered providers are complete, deterministic and semantically typechecked; ${variantCount} configured variants independently typechecked.`);

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
