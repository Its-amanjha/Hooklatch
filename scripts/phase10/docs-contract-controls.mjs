#!/usr/bin/env node
/**
 * Phase10 documentation contract gate - scripted controls (offline).
 *
 * Every control runs the pure checks of `docs-contract.mjs` against
 * purpose-built fixtures and asserts that each defect reaches EXACTLY its
 * intended finding (never a blanket envelope rejection), and that the
 * corrected authored baseline passes with zero findings.
 *
 * Coverage:
 *  - corrected baseline green (markers, tables, 21 IDs in registry order,
 *    literal algorithms, working relative links, fenced examples ignored);
 *  - missing fal/Vercel IDs, wrong algorithm cells, non-literal cells,
 *    duplicate/unknown IDs, wrong order, non-inline-code first cell;
 *  - missing markers, multiple marker pairs, end marker before start marker,
 *    a marker pair and table fully inside a fenced block (no fallback parse),
 *    wrong columns, empty overview region, malformed separator row;
 *  - the bounded global-claim phrases found outside fences and ignored inside
 *    fences, in two different scope files;
 *  - the known missing `docs/diagnostics.md#source-typing-migration-impact`
 *    anchor, unexpected Markdown targets, escaping `../` targets, duplicate
 *    heading slugs (`#notes` and `#notes-1` resolve, `#notes-2` and a missing
 *    slug fail);
 *  - policy/registry desync in both directions so a future provider can never
 *    default silently;
 *  - missing built registry fixture (pure helper returns null) plus real
 *    subprocess runs of the guarded CLI: BLOCKED exit 3 without `dist`, and
 *    RED exit 1 with honest `missing-doc` findings (no conditional pass) on a
 *    temp project without documentation.
 *
 * Scratch safety: subprocess fixtures are created inside one ledgered
 * `mkdtemp` root under the OS temp directory, spawned children are bounded
 * with a timeout, and the root is removed and verified at the end. A cleanup
 * failure fails the run.
 *
 * Exit codes:
 *   0  PASS  - every control reached its intended verdict
 *   1  FAIL  - one or more controls failed, or cleanup was not verified
 */

import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { spawnSync } from 'node:child_process';

import {
  ALGORITHM_POLICY,
  GUIDE_COLUMNS,
  MARKER_END,
  MARKER_START,
  README_COLUMNS,
  checkRelativeLinks,
  readBuiltRegistry,
  runDocsContract,
} from './docs-contract.mjs';

const EXIT = { PASS: 0, FAIL: 1 };
const FENCE = '```';
const CHILD_TIMEOUT_MS = 30000;

/** The frozen contract registry order, asserted equal at run start. */
const CONTROL_REGISTRY = [
  'stripe', 'github', 'shopify', 'standard-webhooks', 'clerk', 'svix', 'razorpay',
  'paddle', 'lemon-squeezy', 'dodo-payments', 'gitlab', 'replicate', 'workos',
  'sentry', 'doppler', 'sanity', 'grafana', 'polar', 'linear', 'vercel', 'fal',
];

/* -------------------------------------------------------------------------- */
/* assertion helpers                                                          */
/* -------------------------------------------------------------------------- */

/** Assert deep equality via stable JSON; throw with the control label. */
function expectEqual(actual, expected, label) {
  const actualJson = JSON.stringify(actual);
  const expectedJson = JSON.stringify(expected);

  if (actualJson !== expectedJson) {
    throw new Error(`${label}: expected ${expectedJson}, got ${actualJson}`);
  }
}

/** Assert one finding carrying every given key/value pair exists. */
function expectFinding(findings, expected, label) {
  const matched = findings.some((finding) => Object.keys(expected)
    .every((key) => JSON.stringify(finding[key]) === JSON.stringify(expected[key])));

  if (!matched) {
    throw new Error(`${label}: no finding equals ${JSON.stringify(expected)}; got ${JSON.stringify(findings)}`);
  }
}

/** Assert no finding of the given kind exists (used for non-blanket checks). */
function expectNoKind(findings, kind, label) {
  const matched = findings.filter((finding) => finding.kind === kind);

  if (matched.length > 0) {
    throw new Error(`${label}: unexpected ${kind} finding: ${JSON.stringify(matched)}`);
  }
}

/* -------------------------------------------------------------------------- */
/* corrected baseline fixtures                                                */
/* -------------------------------------------------------------------------- */

/** Build one authored overview block: markers + header + separator + rows. */
function overviewBlock(columns, rowTexts) {
  const header = `| ${columns.join(' | ')} |`;
  const separatorCells = [];

  for (const column of columns) {
    separatorCells.push('-'.repeat(column.length + 2));
  }

  const separator = `| ${separatorCells.join(' | ')} |`;

  return [MARKER_START, header, separator, ...rowTexts, MARKER_END].join('\n');
}

const README_FILLER = { signed: 'body', credentials: 'literal secret', freshness: 'none', identity: 'null' };
const GUIDE_FILLER = { headers: 'Signature-Header', signed: 'body', credentials: 'literal', identity: 'null' };

/** One README overview row: inline-code ID plus literal algorithm cell. */
function readmeRow(id, algorithm) {
  return `| \`${id}\` | ${algorithm} | ${README_FILLER.signed} | ${README_FILLER.credentials} | ${README_FILLER.freshness} | ${README_FILLER.identity} |`;
}

/** One guide overview row: inline-code ID plus literal algorithm cell. */
function guideRow(id, algorithm) {
  return `| \`${id}\` | ${algorithm} | ${GUIDE_FILLER.headers} | ${GUIDE_FILLER.signed} | ${GUIDE_FILLER.credentials} | ${GUIDE_FILLER.identity} |`;
}

/** Rows for every control registry id, with optional per-id algorithm overrides. */
function buildRows(rowBuilder, overrides) {
  const rows = [];

  for (const id of CONTROL_REGISTRY) {
    const algorithm = overrides !== undefined && overrides[id] !== undefined ? overrides[id] : ALGORITHM_POLICY[id];

    rows.push({ id, text: rowBuilder(id, algorithm) });
  }

  return rows;
}

/** README document for a given row set and optional extra prose. */
function readmeDocument(rows, extraProse) {
  const lines = [
    '# Hooklatch',
    '',
    '**Verify webhooks. Preserve every byte.**',
    '',
    'Portable webhook signature verification with a zero-dependency core.',
    '',
    'See the [provider guide](docs/providers.md), the',
    '[type migration notes](docs/diagnostics.md#source-typing-migration-impact)',
    'and the [CLI reference](docs/cli.md).',
    '',
    '## Quick start',
    '',
    `${FENCE}ts`,
    'const result = await verify(request, options);',
    'All protocols use HMAC-SHA256 inside a fenced example.',
    '[broken inside fence](docs/not-tracked.md)',
    FENCE,
    '',
    '## Overview',
    '',
    overviewBlock(README_COLUMNS, rows.map((row) => row.text)),
    '',
  ];

  if (extraProse !== undefined) {
    lines.push(extraProse, '');
  }

  lines.push('## License', '', 'MIT.');

  return lines.join('\n');
}

/** Guide document for a given row set and optional extra link line. */
function providersDocument(rows, extraLink) {
  const lines = [
    '# Provider guide',
    '',
    'See [CLI scaffolding](cli.md) and [diagnostics](diagnostics.md).',
    '',
    '## Overview',
    '',
    overviewBlock(GUIDE_COLUMNS, rows.map((row) => row.text)),
    '',
  ];

  if (extraLink !== undefined) {
    lines.push(extraLink, '');
  }

  lines.push('## Cross-provider rules', '', 'Exact bytes only.');

  return lines.join('\n');
}

const DIAGNOSTICS_WITH_ANCHOR = [
  '# Diagnostics',
  '',
  '## Source typing migration impact',
  '',
  'VerifyOptions is a provider-discriminated union.',
  '',
  '## Usage',
  '',
  'Import from the diagnostics subpath.',
].join('\n');

const DIAGNOSTICS_PLAIN = [
  '# Diagnostics',
  '',
  '## Usage',
  '',
  'Import from the diagnostics subpath.',
].join('\n');

const CLI_PLAIN = ['# Hooklatch CLI', '', '## Usage', '', '`hooklatch init webhook ...`.'].join('\n');
const CONTRIBUTING_PLAIN = ['# Contributing', '', 'Run npm run verify.'].join('\n');
const SECURITY_PLAIN = ['# Security Policy', '', 'See the reporting section.'].join('\n');

/** The corrected authored six-file baseline. `options` adjusts variants. */
function buildBaselineFiles(options) {
  const settings = options ?? {};

  return {
    'README.md': readmeDocument(buildRows(readmeRow, settings.readmeAlgorithmOverrides), settings.readmeExtraProse),
    'CONTRIBUTING.md': CONTRIBUTING_PLAIN,
    'SECURITY.md': SECURITY_PLAIN,
    'docs/providers.md': providersDocument(buildRows(guideRow, settings.guideAlgorithmOverrides), settings.guideExtraLink),
    'docs/diagnostics.md': settings.withMigrationAnchor === false ? DIAGNOSTICS_PLAIN : DIAGNOSTICS_WITH_ANCHOR,
    'docs/cli.md': settings.cliDocument ?? CLI_PLAIN,
  };
}

/* -------------------------------------------------------------------------- */
/* row-set surgery helpers                                                    */
/* -------------------------------------------------------------------------- */

/** Drop rows by id from a row list. */
function dropRows(rows, ids) {
  const remaining = [];

  for (const row of rows) {
    if (!ids.includes(row.id)) remaining.push(row);
  }

  return remaining;
}

/** Return a new row list where the row with the given id is replaced. */
function replaceRow(rows, id, replacement) {
  const updated = [];

  for (const row of rows) {
    if (row.id === id) {
      updated.push(replacement);
    } else {
      updated.push(row);
    }
  }

  return updated;
}

/** Return a new row list with one row inserted after the row with the id. */
function insertAfter(rows, id, inserted) {
  const updated = [];

  for (const row of rows) {
    updated.push(row);

    if (row.id === id) updated.push(inserted);
  }

  return updated;
}

/** Return a new row list with two rows exchanged by id. */
function swapRows(rows, firstId, secondId) {
  const updated = [...rows];

  const firstIndex = updated.findIndex((row) => row.id === firstId);
  const secondIndex = updated.findIndex((row) => row.id === secondId);

  if (firstIndex === -1 || secondIndex === -1) {
    throw new Error(`swapRows: missing ${firstId} or ${secondId}`);
  }

  const first = updated[firstIndex];
  updated[firstIndex] = updated[secondIndex];
  updated[secondIndex] = first;

  return updated;
}

/* -------------------------------------------------------------------------- */
/* subprocess project fixtures (OS temp, ledgered)                            */
/* -------------------------------------------------------------------------- */

/**
 * Build a standalone temp project hosting a copy of the guarded CLI:
 * scripts/phase10/docs-contract.mjs, and optionally a fake built registry.
 * Returns the absolute CLI path inside the temp project.
 */
async function createTempProject(ledgerArg, registryFixture) {
  const projectRoot = await mkdtemp(path.join(os.tmpdir(), 'hooklatch-phase10-glm-control-'));
  const originalPath = path.resolve(import.meta.dirname, 'docs-contract.mjs');
  const cliPath = path.join(projectRoot, 'scripts', 'phase10', 'docs-contract.mjs');
  const packagePath = path.join(projectRoot, 'package.json');

  ledgerArg.roots.push(projectRoot);

  const source = await readFile(originalPath, { encoding: 'utf8' });

  await mkdir(path.dirname(cliPath), { recursive: true });
  await writeFile(cliPath, source, { encoding: 'utf8' });
  await writeFile(packagePath, '{"type":"module","private":true}\n', { encoding: 'utf8' });

  const created = [cliPath, packagePath];

  if (registryFixture !== undefined) {
    const registryPath = path.join(projectRoot, 'dist', 'providers', 'index.js');
    const registryLines = [`export const SUPPORTED_PROVIDERS = ${JSON.stringify(registryFixture)};`, ''];

    await mkdir(path.dirname(registryPath), { recursive: true });
    await writeFile(registryPath, registryLines.join('\n'), { encoding: 'utf8' });
    created.push(registryPath);
  }

  ledgerArg.files.push(...created);

  return { projectRoot, cliPath };
}

/** Spawn one bounded CLI child and return its real observations. */
function runCliChild(cliPath) {
  return spawnSync(process.execPath, [cliPath], { timeout: CHILD_TIMEOUT_MS, encoding: 'utf8' });
}

/* -------------------------------------------------------------------------- */
/* controls                                                                   */
/* -------------------------------------------------------------------------- */

const ledger = { roots: [], files: [], removed: false };
const controlReports = [];

/** The corrected baseline must be entirely green, links checked sincerely. */
async function controlCorrectedBaselineGreen() {
  const report = runDocsContract(buildBaselineFiles(), CONTROL_REGISTRY, ALGORITHM_POLICY);

  expectEqual(report.findings, [], 'corrected baseline has zero findings');
  expectEqual(
    report.linkTotals,
    { checked: 5, skippedExternal: 0, skippedTargetsOutsideScope: 0 },
    'corrected baseline link totals',
  );
}

/** README without the vercel and fal rows must miss exactly those two ids. */
async function controlMissingFalVercelIds() {
  const baseline = buildBaselineFiles();
  const readme = readmeDocument(dropRows(buildRows(readmeRow), ['vercel', 'fal']));
  const report = runDocsContract({ ...baseline, 'README.md': readme }, CONTROL_REGISTRY, ALGORITHM_POLICY);

  expectFinding(
    report.findings,
    { kind: 'missing-ids', file: 'README.md', missing: ['vercel', 'fal'] },
    'missing fal/Vercel rows',
  );
}

/** Vercel listed as HMAC-SHA256 must reach the exact algorithm-policy defect. */
async function controlWrongAlgorithmVercel() {
  const baseline = buildBaselineFiles({ readmeAlgorithmOverrides: { vercel: 'HMAC-SHA256' } });
  const report = runDocsContract(baseline, CONTROL_REGISTRY, ALGORITHM_POLICY);

  expectFinding(
    report.findings,
    { kind: 'algorithm-policy', file: 'README.md', id: 'vercel', expected: 'HMAC-SHA1', observed: 'HMAC-SHA256' },
    'wrong vercel algorithm in README overview',
  );
}

/** fal listed as HMAC-SHA256 must reach the exact algorithm-policy defect. */
async function controlWrongAlgorithmFal() {
  const baseline = buildBaselineFiles({ guideAlgorithmOverrides: { fal: 'HMAC-SHA256' } });
  const report = runDocsContract(baseline, CONTROL_REGISTRY, ALGORITHM_POLICY);

  expectFinding(
    report.findings,
    { kind: 'algorithm-policy', file: 'docs/providers.md', id: 'fal', expected: 'Ed25519', observed: 'HMAC-SHA256' },
    'wrong fal algorithm in guide overview',
  );
}

/** A decorated algorithm cell must reach the exact algorithm-literal defect. */
async function controlNonLiteralAlgorithmCell() {
  const baseline = buildBaselineFiles({ guideAlgorithmOverrides: { grafana: 'HMAC-SHA256 (colon form)' } });
  const report = runDocsContract(baseline, CONTROL_REGISTRY, ALGORITHM_POLICY);

  expectFinding(
    report.findings,
    { kind: 'algorithm-literal', file: 'docs/providers.md', id: 'grafana', observed: 'HMAC-SHA256 (colon form)' },
    'non-literal grafana algorithm cell',
  );
}

/** A duplicated id row must reach the exact duplicate-ids defect. */
async function controlDuplicateId() {
  const rows = buildRows(readmeRow);
  const rowsWithDuplicate = insertAfter(rows, 'paddle', { id: 'paddle', text: rows[7].text });
  const baseline = buildBaselineFiles();

  const report = runDocsContract(
    { ...baseline, 'README.md': readmeDocument(rowsWithDuplicate) },
    CONTROL_REGISTRY,
    ALGORITHM_POLICY,
  );

  expectFinding(report.findings, { kind: 'duplicate-ids', file: 'README.md', duplicates: ['paddle'] }, 'duplicated paddle row');
  expectNoKind(report.findings, 'id-order', 'a duplicate keeps the unique order intact');
}

/** A row with an outside-registry id must reach the exact unknown-ids defect. */
async function controlUnknownId() {
  const rows = insertAfter(buildRows(readmeRow), 'fal', { id: 'acme', text: readmeRow('acme', 'HMAC-SHA256') });
  const baseline = buildBaselineFiles();
  const report = runDocsContract({ ...baseline, 'README.md': readmeDocument(rows) }, CONTROL_REGISTRY, ALGORITHM_POLICY);

  expectFinding(report.findings, { kind: 'unknown-ids', file: 'README.md', unknown: ['acme'] }, 'unknown acme row');
  expectNoKind(report.findings, 'missing-ids', 'an extra id does not hide any registry id');
}

/** Two swapped rows must reach the exact id-order defect. */
async function controlIdOrder() {
  const rows = swapRows(buildRows(readmeRow), 'stripe', 'github');
  const baseline = buildBaselineFiles();
  const report = runDocsContract({ ...baseline, 'README.md': readmeDocument(rows) }, CONTROL_REGISTRY, ALGORITHM_POLICY);

  const observedOrder = [...CONTROL_REGISTRY];
  const first = observedOrder[0];
  observedOrder[0] = observedOrder[1];
  observedOrder[1] = first;

  expectFinding(
    report.findings,
    { kind: 'id-order', file: 'README.md', expected: CONTROL_REGISTRY.slice(), observed: observedOrder },
    'swapped stripe/github rows',
  );
  expectNoKind(report.findings, 'missing-ids', 'a swap leaves every id present');
}

/** A plain (non inline-code) first cell must reach first-cell plus missing ids. */
async function controlPlainFirstCell() {
  const rows = replaceRow(buildRows(readmeRow), 'stripe', {
    id: '',
    text: '| stripe | HMAC-SHA256 | body | literal secret | none | null |',
  });

  const baseline = buildBaselineFiles();
  const report = runDocsContract({ ...baseline, 'README.md': readmeDocument(rows) }, CONTROL_REGISTRY, ALGORITHM_POLICY);

  expectFinding(
    report.findings,
    { kind: 'first-cell', file: 'README.md', detail: 'first-cell-not-inline-code' },
    'plain stripe first cell',
  );

  const missingFinding = report.findings.find((finding) => finding.kind === 'missing-ids');

  if (missingFinding === undefined || !missingFinding.missing.includes('stripe')) {
    throw new Error(`plain first cell: expected missing-ids to include stripe; got ${JSON.stringify(report.findings)}`);
  }
}

/** A marker pair and fake table fully inside a fence must yield markers 0/0 and no parsed rows. */
async function controlFencedHighjacking() {
  const fenced = [
    '# Hooklatch',
    '',
    FENCE,
    MARKER_START,
    '| Provider | Algorithm | Signed content | Credentials | Freshness | Identity |',
    '| -------- | --------- | -------------- | ----------- | --------- | -------- |',
    '| zebra | HMAC-SHA256 | body | literal | none | null |',
    '| `zebra` | HMAC-SHA256 | body | literal | none | null |',
    MARKER_END,
    FENCE,
    '',
    'See the [provider guide](docs/providers.md).',
  ].join('\n');

  const baseline = buildBaselineFiles();
  const report = runDocsContract({ ...baseline, 'README.md': fenced }, CONTROL_REGISTRY, ALGORITHM_POLICY);

  expectFinding(report.findings, { kind: 'markers', file: 'README.md', starts: 0, ends: 0 }, 'fenced fake pair invisible');
  expectNoKind(report.findings, 'unknown-ids', 'fenced zebra rows are not parsed');
  expectNoKind(report.findings, 'first-cell', 'fenced rows do not run row checks');
  expectNoKind(report.findings, 'duplicate-ids', 'fenced rows do not pollute counts');
}

/** Two marker pairs in one document must reach markers with both counts at 2. */
async function controlMultipleMarkers() {
  const first = overviewBlock(README_COLUMNS, buildRows(readmeRow).map((row) => row.text));
  const second = overviewBlock(README_COLUMNS, buildRows(readmeRow).map((row) => row.text));

  const markdown = ['# Hooklatch', '', first, '', second, ''].join('\n');
  const baseline = buildBaselineFiles();
  const report = runDocsContract({ ...baseline, 'README.md': markdown }, CONTROL_REGISTRY, ALGORITHM_POLICY);

  expectFinding(report.findings, { kind: 'markers', file: 'README.md', starts: 2, ends: 2 }, 'two marker pairs');
}

/** End marker before start marker must reach the markers finding. */
async function controlEndBeforeStart() {
  const markdown = ['# Hooklatch', '', MARKER_END, '', MARKER_START, ''].join('\n');
  const baseline = buildBaselineFiles();
  const report = runDocsContract({ ...baseline, 'README.md': markdown }, CONTROL_REGISTRY, ALGORITHM_POLICY);

  expectFinding(report.findings, { kind: 'markers', file: 'README.md', starts: 1, ends: 1 }, 'start/end order rejected');
}

/** A five-column guide header must reach the exact columns defect. */
async function controlWrongColumns() {
  const rows = buildRows(guideRow).map((row) => row.text);

  const markdown = [
    '# Provider guide',
    '',
    MARKER_START,
    '| ID | Algorithm | Signed content | Credentials | Identity |',
    '| --- | --------- | -------------- | ----------- | -------- |',
    ...rows,
    MARKER_END,
    '',
  ].join('\n');

  const baseline = buildBaselineFiles();
  const report = runDocsContract({ ...baseline, 'docs/providers.md': markdown }, CONTROL_REGISTRY, ALGORITHM_POLICY);

  expectFinding(
    report.findings,
    {
      kind: 'columns',
      file: 'docs/providers.md',
      expected: GUIDE_COLUMNS,
      observed: ['ID', 'Algorithm', 'Signed content', 'Credentials', 'Identity'],
    },
    'five-column guide header',
  );
}

/** An empty overview region must reach the exact no-table defect. */
async function controlEmptyOverviewRegion() {
  const markdown = ['# Provider guide', '', MARKER_START, '', MARKER_END, ''].join('\n');
  const baseline = buildBaselineFiles();
  const report = runDocsContract({ ...baseline, 'docs/providers.md': markdown }, CONTROL_REGISTRY, ALGORITHM_POLICY);

  expectFinding(
    report.findings,
    { kind: 'table', file: 'docs/providers.md', detail: 'overview region contains no table' },
    'empty marker region',
  );
}

/** A malformed separator row must reach the exact malformed-separator defect. */
async function controlMalformedSeparator() {
  const rows = buildRows(guideRow).map((row) => row.text);

  const markdown = [
    '# Provider guide',
    '',
    MARKER_START,
    `| ${GUIDE_COLUMNS.join(' | ')} |`,
    '| x | x | x | x | x | x |',
    ...rows,
    MARKER_END,
    '',
  ].join('\n');

  const baseline = buildBaselineFiles();
  const report = runDocsContract({ ...baseline, 'docs/providers.md': markdown }, CONTROL_REGISTRY, ALGORITHM_POLICY);

  expectFinding(
    report.findings,
    { kind: 'table', file: 'docs/providers.md', detail: 'overview table separator row is malformed' },
    'malformed separator row',
  );
}

/** The bounded all-protocols claim in README prose must reach global-claim. */
async function controlGlobalClaimReadme() {
  const baseline = buildBaselineFiles({
    readmeExtraProse: 'Marketing aside: All protocols use HMAC-SHA256 for compatibility.',
  });

  const report = runDocsContract(baseline, CONTROL_REGISTRY, ALGORITHM_POLICY);

  expectFinding(
    report.findings,
    { kind: 'global-claim', file: 'README.md', claim: 'all-protocols-HMAC-SHA256', text: 'All protocols use HMAC-SHA256' },
    'all-protocols claim in README prose',
  );
}

/** The all-providers claim pattern must be found in another scope file. */
async function controlGlobalClaimOtherFile() {
  const cliDocument = [CLI_PLAIN, '', 'History note: earlier drafts said all providers use HMAC-SHA256.', ''].join('\n');
  const baseline = buildBaselineFiles({ cliDocument });
  const report = runDocsContract(baseline, CONTROL_REGISTRY, ALGORITHM_POLICY);

  expectFinding(
    report.findings,
    { kind: 'global-claim', file: 'docs/cli.md', claim: 'all-providers-HMAC-SHA256' },
    'all-providers claim in cli.md prose',
  );
}

/** The identical claim inside a fence must produce zero global-claim findings. */
async function controlFencedClaimIgnored() {
  const cliDocument = ['# Hooklatch CLI', '', FENCE, 'History note: all providers use HMAC-SHA256.', FENCE, ''].join('\n');
  const baseline = buildBaselineFiles({ cliDocument });
  const report = runDocsContract(baseline, CONTROL_REGISTRY, ALGORITHM_POLICY);

  expectNoKind(report.findings, 'global-claim', 'fenced claim is ignored');
  expectEqual(report.findings, [], 'fenced-claim fixture stays entirely green');
}

/** The known missing migration anchor must reach the exact broken-heading-anchor defect. */
async function controlBrokenMigrationAnchor() {
  const baseline = buildBaselineFiles({ withMigrationAnchor: false });
  const report = runDocsContract(baseline, CONTROL_REGISTRY, ALGORITHM_POLICY);

  expectFinding(
    report.findings,
    {
      kind: 'broken-heading-anchor',
      file: 'README.md',
      target: 'docs/diagnostics.md#source-typing-migration-impact',
      fragment: 'source-typing-migration-impact',
      resolved: 'docs/diagnostics.md',
    },
    'known missing migration anchor',
  );
}

/** A Markdown target outside the tracked scope must reach unexpected-markdown-target. */
async function controlUnexpectedMarkdownTarget() {
  const baseline = buildBaselineFiles({
    readmeExtraProse: 'Private: see [internal notes](docs/not-tracked.md).',
  });

  const report = runDocsContract(baseline, CONTROL_REGISTRY, ALGORITHM_POLICY);

  expectFinding(
    report.findings,
    { kind: 'unexpected-markdown-target', file: 'README.md', resolved: 'docs/not-tracked.md' },
    'markdown link outside the tracked scope',
  );
}

/** A resolved `../` escape must reach the exact escaping-link-target defect. */
async function controlEscapingTarget() {
  const baseline = buildBaselineFiles({
    guideExtraLink: 'Root reference: [readme](../../README.md).',
  });

  const report = runDocsContract(baseline, CONTROL_REGISTRY, ALGORITHM_POLICY);

  expectFinding(
    report.findings,
    { kind: 'escaping-link-target', file: 'docs/providers.md', target: '../../README.md', resolved: '../README.md' },
    'escaping relative target',
  );
}

/** Duplicate heading slugs: `#notes` and `#notes-1` resolve; `#notes-2` and a missing slug fail. */
async function controlDuplicateHeadingSlugs() {
  const document = [
    '# Notes',
    '',
    '[first](#notes) [second](#notes-1) [too far](#notes-2) [never](#absent)',
    '',
    '## Notes',
    '',
    '## Other notes',
  ].join('\n');

  const report = checkRelativeLinks(document, 'docs/extra.md', new Map());

  expectEqual(report.counts.checked, 2, 'fragment links checked');
  expectEqual(
    report.findings.map((finding) => finding.fragment),
    ['notes-2', 'absent'],
    'duplicate-slug findings exact fragments',
  );
}

/** A registry with an extra future provider must reach policy-registry-desync. */
async function controlRegistryExtraDesync() {
  const futureRegistry = [...CONTROL_REGISTRY, 'acme'];
  const report = runDocsContract(buildBaselineFiles(), futureRegistry, ALGORITHM_POLICY);

  expectFinding(
    report.findings,
    { kind: 'policy-registry-desync', direction: 'registry-only', ids: ['acme'] },
    'registry exceeds the frozen policy',
  );
}

/** A policy with an extra key must reach the mirrored policy-registry-desync. */
async function controlPolicyExtraDesync() {
  const driftedPolicy = { ...ALGORITHM_POLICY, acme: 'HMAC-SHA256' };
  const report = runDocsContract(buildBaselineFiles(), CONTROL_REGISTRY, driftedPolicy);

  expectFinding(
    report.findings,
    { kind: 'policy-registry-desync', direction: 'policy-only', ids: ['acme'] },
    'policy exceeds the built registry',
  );
}

/** A temp project without dist must behave as the unavailable built registry. */
async function controlBuiltRegistryUnavailable(ledgerArg) {
  const project = await createTempProject(ledgerArg);
  const registry = await readBuiltRegistry(project.projectRoot);

  if (registry !== null) {
    throw new Error(`readBuiltRegistry returned ${JSON.stringify(registry)} for a root without dist`);
  }
}

/** Real subprocess: no dist means BLOCKED exit 3 with machine JSON. */
async function controlCliBlockedExit3(ledgerArg) {
  const project = await createTempProject(ledgerArg);
  const child = runCliChild(project.cliPath);

  if (child.error !== undefined) {
    throw new Error(`cli-blocked: child failed to spawn: ${String(child.error)}`);
  }

  if (child.status !== 3) {
    throw new Error(`cli-blocked: expected status 3 (BLOCKED), got ${JSON.stringify(child.status)}; signal ${JSON.stringify(child.signal)}`);
  }

  const report = JSON.parse(child.stdout);

  expectEqual(report.status, 'blocked', 'cli blocked status');
  expectEqual(report.exit, 3, 'cli blocked exit field');
}

/** Real subprocess: a registry without documentation must exit 1 with missing-doc findings. */
async function controlCliRedMissingDocs(ledgerArg) {
  const project = await createTempProject(ledgerArg, CONTROL_REGISTRY);
  const child = runCliChild(project.cliPath);

  if (child.error !== undefined) {
    throw new Error(`cli-red: child failed to spawn: ${String(child.error)}`);
  }

  if (child.status !== 1) {
    throw new Error(`cli-red: expected status 1 (RED), got ${JSON.stringify(child.status)}; signal ${JSON.stringify(child.signal)}`);
  }

  const report = JSON.parse(child.stdout);

  expectEqual(report.status, 'fail', 'cli red status with missing docs');
  expectFinding(report.findings, { kind: 'missing-doc', file: 'README.md' }, 'cli red missing-doc README');
  expectFinding(report.findings, { kind: 'missing-doc', file: 'docs/providers.md' }, 'cli red missing-doc guide');
  expectNoKind(report.findings, 'policy-registry-desync', 'the real frozen policy stays in sync');
}

/* -------------------------------------------------------------------------- */
/* driver                                                                     */
/* -------------------------------------------------------------------------- */

const CONTROLS = [
  controlCorrectedBaselineGreen,
  controlMissingFalVercelIds,
  controlWrongAlgorithmVercel,
  controlWrongAlgorithmFal,
  controlNonLiteralAlgorithmCell,
  controlDuplicateId,
  controlUnknownId,
  controlIdOrder,
  controlPlainFirstCell,
  controlFencedHighjacking,
  controlMultipleMarkers,
  controlEndBeforeStart,
  controlWrongColumns,
  controlEmptyOverviewRegion,
  controlMalformedSeparator,
  controlGlobalClaimReadme,
  controlGlobalClaimOtherFile,
  controlFencedClaimIgnored,
  controlBrokenMigrationAnchor,
  controlUnexpectedMarkdownTarget,
  controlEscapingTarget,
  controlDuplicateHeadingSlugs,
  controlRegistryExtraDesync,
  controlPolicyExtraDesync,
  () => controlBuiltRegistryUnavailable(ledger),
  () => controlCliBlockedExit3(ledger),
  () => controlCliRedMissingDocs(ledger),
];

const CONTROL_NAMES = [
  'corrected-baseline-green',
  'missing-fal-vercel-ids',
  'wrong-algorithm-vercel-readme',
  'wrong-algorithm-fal-guide',
  'algorithm-literal-grafana-guide',
  'duplicate-id-paddle',
  'unknown-id-acme',
  'id-order-swapped',
  'first-cell-not-inline-code',
  'fenced-pair-and-table',
  'markers-multiple',
  'markers-end-before-start',
  'columns-wrong-guide',
  'overview-region-empty-guide',
  'separator-malformed-guide',
  'global-claim-readme',
  'global-claim-cli',
  'fenced-claim-ignored',
  'broken-migration-anchor',
  'unexpected-markdown-target',
  'escaping-link-target',
  'duplicate-heading-slugs',
  'policy-desync-registry-extra',
  'policy-desync-policy-extra',
  'built-registry-unavailable-null',
  'cli-blocked-exit3',
  'cli-red-missing-docs',
];

async function main() {
  if (CONTROLS.length !== CONTROL_NAMES.length) {
    throw new Error(`internal desync: ${CONTROLS.length} controls but ${CONTROL_NAMES.length} names`);
  }

  expectEqual(policyAlgorithmCounts(), { 'HMAC-SHA256': 19, 'HMAC-SHA1': 1, Ed25519: 1 }, 'frozen policy algorithm counts');

  for (let index = 0; index < CONTROLS.length; index += 1) {
    const name = CONTROL_NAMES[index];

    try {
      await CONTROLS[index]();

      controlReports.push({ name, verdict: 'pass', error: '' });
    } catch (error) {
      controlReports.push({ name, verdict: 'fail', error: String(error) });
    }
  }

  const passed = controlReports.filter((entry) => entry.verdict === 'pass').length;
  const failedControls = controlReports.filter((entry) => entry.verdict === 'fail');

  let cleanupVerified = false;

  if (ledger.roots.length > 0) {
    try {
      await Promise.all(ledger.roots.map((root) => rm(root, { recursive: true, force: false })));
    } catch {
      cleanupVerified = false;
    }

    const leftover = [];

    for (const root of ledger.roots) {
      if (existsSync(root)) leftover.push(root);
    }

    if (leftover.length === 0) {
      cleanupVerified = true;
      ledger.removed = true;
    }
  } else {
    cleanupVerified = true;
  }

  const status = passed === CONTROLS.length && cleanupVerified ? 'pass' : 'fail';

  console.log(JSON.stringify({
    schemaVersion: 1,
    phase: 'phase-10 documentation contract controls',
    status,
    exit: status === 'pass' ? EXIT.PASS : EXIT.FAIL,
    summary: {
      controls: controlReports.length,
      passed,
      failed: failedControls.length,
      cleanupVerified,
      ledger: { tempRoots: ledger.roots.length, filesCreated: ledger.files.length },
    },
    controls: controlReports,
  }, null, 2));

  process.exitCode = status === 'pass' ? EXIT.PASS : EXIT.FAIL;
}

/** Count the frozen policy algorithm values without filter/map pipelines. */
function policyAlgorithmCounts() {
  const counts = { 'HMAC-SHA256': 0, 'HMAC-SHA1': 0, Ed25519: 0 };

  for (const algorithm of Object.values(ALGORITHM_POLICY)) {
    counts[algorithm] += 1;
  }

  return counts;
}

await main();
