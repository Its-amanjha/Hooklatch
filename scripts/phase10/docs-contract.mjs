#!/usr/bin/env node
/**
 * Phase10 documentation drift contract gate (offline).
 *
 * Checks the tracked Markdown documentation against the shipped provider
 * contract without running the SDK or touching the network:
 *
 *  - Overview marker pairs outside fenced code (README.md, docs/providers.md).
 *  - Overview table shape, canonical inline-code provider IDs in built
 *    registry order, and literal algorithm cells per the frozen policy map.
 *  - Policy map keys are compared against the BUILT registry
 *    (`dist/providers/index.js` `SUPPORTED_PROVIDERS`) in both directions so a
 *    future provider never defaults silently. Missing built registry is
 *    BLOCKED, never a pass.
 *  - A bounded global-claim scan rejects "all protocols use HMAC-SHA256"
 *    style claims outside fenced code. No other prose is judged.
 *  - Relative tracked Markdown file and heading-anchor links across
 *    README.md, docs/providers.md, docs/diagnostics.md, docs/cli.md,
 *    CONTRIBUTING.md, SECURITY.md, docs/api-stability.md, docs/credential-recipes.md
 *    and CHANGELOG.md, excluding fenced examples. Fragment-only
 *    links resolve within the same document; duplicate heading slugs follow
 *    `-1`, `-2` numbering.
 *
 * Known base failures (drift): the marker pairs are absent, the README
 * declares "All protocols use HMAC-SHA256", and the README links to the
 * absent `docs/diagnostics.md#source-typing-migration-impact` anchor. The gate
 * must stay RED until the Nemotron documentation corrections integrate.
 *
 * Supported Markdown limits (documented, bounded):
 *  - Fences: ``` and ~~~ toggles with matching closing tokens. Indented fences
 *    and fence edge cases (fences inside fences) are not modeled.
 *  - Headings: `#`-style lines only; setext headings are not parsed.
 *  - Links: inline `[text](target)` only. Reference-style links are not
 *    parsed at all; images and non-Markdown targets are outside the checked
 *    scope and counted as skipped targets.
 *  - Slugger: GitHub-style ASCII approximation. Unicode letters and exotic
 *    punctuation are stripped rather than percent-encoded, so anchors for such
 *    headings may diverge from github.com rendering.
 *  - Link targets must stay inside the fixed tracked Markdown scope;
 *    other Markdown targets are reported as drift, not silently passed.
 *
 * Exit codes:
 *   0  PASS    - no contract findings
 *   1  RED     - findings exist (expected for the current documentation until
 *                the corrections integrate)
 *   2  USAGE   - invalid CLI invocation
 *   3  BLOCKED - required prerequisite absent (built registry)
 *
 * The CLI prints one machine-JSON report on stdout for exits 0/1/3; usage
 * errors print a single line on stderr with exit 2. This is a documentation
 * contract, not shadow runtime registration.
 */

import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

const EXIT = { PASS: 0, RED: 1, USAGE: 2, BLOCKED: 3 };

export const MARKER_START = '<!-- hooklatch:provider-table:start -->';
export const MARKER_END = '<!-- hooklatch:provider-table:end -->';

export const README_COLUMNS = ['Provider', 'Algorithm', 'Signed content', 'Credentials', 'Freshness', 'Identity'];
export const GUIDE_COLUMNS = ['ID', 'Algorithm', 'Headers', 'Signed content', 'Credentials', 'Identity'];

/** Frozen per-provider algorithm policy; every policy key is exact. */
export const ALGORITHM_POLICY = Object.freeze({
  stripe: 'HMAC-SHA256',
  github: 'HMAC-SHA256',
  shopify: 'HMAC-SHA256',
  'standard-webhooks': 'HMAC-SHA256',
  clerk: 'HMAC-SHA256',
  svix: 'HMAC-SHA256',
  razorpay: 'HMAC-SHA256',
  paddle: 'HMAC-SHA256',
  'lemon-squeezy': 'HMAC-SHA256',
  'dodo-payments': 'HMAC-SHA256',
  gitlab: 'HMAC-SHA256',
  replicate: 'HMAC-SHA256',
  workos: 'HMAC-SHA256',
  sentry: 'HMAC-SHA256',
  doppler: 'HMAC-SHA256',
  sanity: 'HMAC-SHA256',
  grafana: 'HMAC-SHA256',
  polar: 'HMAC-SHA256',
  linear: 'HMAC-SHA256',
  vercel: 'HMAC-SHA1',
  fal: 'Ed25519',
});

const LITERAL_ALGORITHMS = ['HMAC-SHA256', 'HMAC-SHA1', 'Ed25519'];

/** Bounded global-claim phrases; the scan never judges any other prose. */
const GLOBAL_CLAIM_PATTERNS = [
  { pattern: /all\s+protocols?\s+(?:are|use|uses)\s+HMAC-SHA256/gi, kind: 'all-protocols-HMAC-SHA256' },
  { pattern: /all\s+incoming\s+webhooks?\s+(?:are|use|uses)\s+HMAC-SHA256/gi, kind: 'all-protocols-HMAC-SHA256' },
  {
    pattern: /all\s+(?:of\s+the\s+)?(?:supported\s+)?providers?\s+(?:are|use|uses)\s+HMAC-SHA256/gi,
    kind: 'all-providers-HMAC-SHA256',
  },
  { pattern: /every\s+(?:protocol|provider)\s+(?:is|uses?)\s+HMAC-SHA256/gi, kind: 'every-provider-HMAC-SHA256' },
  { pattern: /all\s+signatures?\s+(?:are|use)\s+HMAC-SHA256/gi, kind: 'all-signatures-HMAC-SHA256' },
];

export const DOC_SCOPE = ['README.md', 'CONTRIBUTING.md', 'SECURITY.md', 'docs/providers.md', 'docs/diagnostics.md', 'docs/cli.md', 'docs/api-stability.md', 'docs/credential-recipes.md', 'CHANGELOG.md', 'docs/compatibility.md', 'docs/verification-evidence.md', 'docs/release-checklist.md'];

const REGISTRY_RELATIVE = 'dist/providers/index.js';


/* -------------------------------------------------------------------------- */
/* fence state                                                               */
/* -------------------------------------------------------------------------- */

/** Return `{outside, inside, fenceLines}` for fenced vs unfenced source. */
function splitFences(text) {
  const lines = text.split(/\r?\n/);
  let inside = false;
  let token = '';
  const outside = [];
  const insideText = [];
  const fenceLines = [];

  for (const line of lines) {
    const opener = /^( {0,3})(`{3,}|~{3,})(.*)$/.exec(line);

    if (inside) {
      insideText.push(line);

      if (opener !== null && opener[2].startsWith(token) && opener[3].trim() === '') {
        inside = false;
        token = '';
        fenceLines.push(line);
        continue;
      }

      continue;
    }

    if (opener !== null) {
      inside = true;
      token = opener[2];
      fenceLines.push(line);
      insideText.push(line);
      continue;
    }

    outside.push(line);
  }

  return { outside: outside.join('\n'), inside: insideText.join('\n'), fenceLines };
}

/* -------------------------------------------------------------------------- */
/* overview tables                                                            */
/* -------------------------------------------------------------------------- */

/** Parse the overview region between exactly one marker pair. Returns
 * `{ok:true, table}` or `{ok:false, findings}`. There is no table fallback
 * outside the markers.
 */
export function parseOverviewRegion(text, columns, file) {
  const { starts, ends } = markerPositions(text);

  if (starts.length !== 1 || ends.length !== 1 || ends[0] <= starts[0]) {
    return { ok: false, findings: [{ kind: 'markers', file, starts: starts.length, ends: ends.length }] };
  }

  const { outside } = splitFences(text);
  const regionLines = outside.split('\n').slice(starts[0] + 1, ends[0]);
  const rows = regionLines.filter((line) => /^\s*\|.*\|\s*$/.test(line));

  if (rows.length < 2) {
    return { ok: false, findings: [{ kind: 'table', file, detail: 'overview region contains no table' }] };
  }

  const headerNames = parseRow(rows[0]).map((cell) => cell.trim());

  let headerMatches = headerNames.length === columns.length;

  for (let index = 0; headerMatches && index < columns.length; index += 1) {
    headerMatches = headerNames[index] === columns[index];
  }

  if (!headerMatches) {
    return { ok: false, findings: [{ kind: 'columns', file, expected: columns, observed: headerNames }] };
  }

  const separatorCells = parseRow(rows[1]);

  let separatorValid = separatorCells.length === columns.length;

  for (const separatorCell of separatorCells) {
    separatorValid = separatorValid && /^:?-+:?$/.test(separatorCell.trim());
  }

  if (!separatorValid) {
    return { ok: false, findings: [{ kind: 'table', file, detail: 'overview table separator row is malformed' }] };
  }

  const data = [];

  for (const row of rows.slice(2)) {
    const cells = parseRow(row);

    if (cells.length !== columns.length) {
      data.push({ id: '', cells, idState: 'wrong-column-count' });
      continue;
    }

    const id = inlineCodeValue(cells[0]);

    data.push({ id, cells, idState: id === '' ? 'first-cell-not-inline-code' : 'ok' });
  }

  return { ok: true, table: { file, columns: headerNames, rows: data }, findings: [] };
}

/** Index positions of marker lines outside fences (duplicates included). */
function markerPositions(text) {
  const { outside } = splitFences(text);
  const lines = outside.split('\n');
  const starts = [];
  const ends = [];

  for (let index = 0; index < lines.length; index += 1) {
    if (lines[index].trim() === MARKER_START) starts.push(index);

    if (lines[index].trim() === MARKER_END) ends.push(index);
  }

  return { starts, ends };
}

/** Split one `|`-delimited Markdown row into raw cell texts. */
function parseRow(line) {
  const trimmed = line.trim();

  if (!trimmed.startsWith('|')) return [];

  const body = trimmed.endsWith('|') ? trimmed.slice(1, -1) : trimmed.slice(1);

  return splitCells(body);
}

/** Split a row body on unescaped pipes; backtick spans and '\\' protect them. */
function splitCells(body) {
  const cells = [];
  let current = '';
  let inCode = false;

  for (let index = 0; index < body.length; index += 1) {
    const character = body[index];

    if (character === '`') {
      inCode = !inCode;
      current += character;
      continue;
    }

    if (character === '\\' && index + 1 < body.length) {
      current += character + body[index + 1];
      index += 1;
      continue;
    }

    if (character === '|' && !inCode) {
      cells.push(current);
      current = '';
      continue;
    }

    current += character;
  }

  cells.push(current);

  return cells;
}

/** Inner text of a single unbroken inline-code span, else ''. */
function inlineCodeValue(cell) {
  const match = /^`([^`]*)`$/.exec(cell.trim());

  if (match === null) return '';

  return match[1];
}

/* -------------------------------------------------------------------------- */
/* overview contract against registry and policy                              */
/* -------------------------------------------------------------------------- */

/**
 * Compare one parsed overview against the built registry order and the
 * frozen algorithm policy. Findings are exact; no silent defaults.
 */
export function checkOverview(table, registry, policy) {
  const findings = [];

  const parsedIds = [];
  const counts = new Map();

  for (const row of table.rows) {
    if (row.idState !== 'ok') {
      findings.push({ kind: 'first-cell', file: table.file, detail: row.idState });
      continue;
    }

    parsedIds.push(row.id);
  }

  for (const id of parsedIds) {
    counts.set(id, (counts.get(id) ?? 0) + 1);
  }

  const duplicates = [];

  for (const [id, count] of counts.entries()) {
    if (count > 1) duplicates.push(id);
  }

  if (duplicates.length > 0) {
    findings.push({ kind: 'duplicate-ids', file: table.file, duplicates });
  }

  const unknown = [];

  for (const id of parsedIds) {
    if (!registry.includes(id)) unknown.push(id);
  }

  if (unknown.length > 0) {
    findings.push({ kind: 'unknown-ids', file: table.file, unknown });
  }

  const missing = [];

  for (const id of registry) {
    if (!counts.has(id)) missing.push(id);
  }

  if (missing.length > 0) {
    findings.push({ kind: 'missing-ids', file: table.file, missing });
  }

  const expectedOrder = [];

  for (const id of registry) {
    if (counts.get(id) === 1) expectedOrder.push(id);
  }

  const observedUnique = [];

  for (const id of parsedIds) {
    if (registry.includes(id) && counts.get(id) === 1) observedUnique.push(id);
  }

  let ordered = observedUnique.length === expectedOrder.length;

  for (let index = 0; ordered && index < expectedOrder.length; index += 1) {
    ordered = observedUnique[index] === expectedOrder[index];
  }

  if (!ordered) {
    findings.push({ kind: 'id-order', file: table.file, expected: expectedOrder, observed: observedUnique });
  }

  for (const row of table.rows) {
    if (row.idState !== 'ok' || !registry.includes(row.id)) continue;

    const algorithmCell = row.cells[1].trim();
    const literal = literalAlgorithmValue(algorithmCell);

    if (!LITERAL_ALGORITHMS.includes(literal)) {
      findings.push({ kind: 'algorithm-literal', file: table.file, id: row.id, observed: algorithmCell });
    } else if (policy[row.id] !== literal) {
      findings.push({ kind: 'algorithm-policy', file: table.file, id: row.id, expected: policy[row.id], observed: literal });
    }
  }

  return findings;
}

/** Accept exactly one literal algorithm cell content (optionally inline code). */
function literalAlgorithmValue(cell) {
  const inline = inlineCodeValue(cell);

  if (inline !== '') return inline;

  return cell;
}

/** Compare frozen policy keys with the built registry keys (both directions). */
export function checkPolicyRegistrySync(registry, policy) {
  const findings = [];

  const policyOnly = [];

  for (const id of Object.keys(policy)) {
    if (!registry.includes(id)) policyOnly.push(id);
  }

  if (policyOnly.length > 0) {
    findings.push({ kind: 'policy-registry-desync', direction: 'policy-only', ids: policyOnly });
  }

  const registryOnly = [];

  for (const id of registry) {
    if (!Object.hasOwn(policy, id)) registryOnly.push(id);
  }

  if (registryOnly.length > 0) {
    findings.push({ kind: 'policy-registry-desync', direction: 'registry-only', ids: registryOnly });
  }

  return findings;
}

/* -------------------------------------------------------------------------- */
/* global-claim scan                                                          */
/* -------------------------------------------------------------------------- */

/** Reject the bounded global HMAC-SHA256 claim phrases outside fenced code. */
export function checkGlobalClaims(text, file) {
  const { outside } = splitFences(text);
  const findings = [];

  for (const claim of GLOBAL_CLAIM_PATTERNS) {
    claim.pattern.lastIndex = 0;

    let match = claim.pattern.exec(outside);

    while (match !== null) {
      findings.push({ kind: 'global-claim', file, claim: claim.kind, text: match[0] });
      match = claim.pattern.exec(outside);
    }
  }

  return findings;
}

/* -------------------------------------------------------------------------- */
/* heading slugs and relative links                                           */
/* -------------------------------------------------------------------------- */

/** GitHub-flavoured ASCII slug for one heading text (documented limits). */
function slugify(headingText) {
  let slug = '';

  for (const character of headingText.trim().toLowerCase()) {
    const keep = (character >= 'a' && character <= 'z')
      || (character >= '0' && character <= '9')
      || character === '-'
      || character === ' '
      || character === '\t';

    slug += keep ? (character === '\t' ? '-' : character) : '';
  }

  return slug.replaceAll(' ', '-');
}

/** Duplicate-aware slugs for `#`-style headings outside fences. */
export function collectHeadings(text) {
  const { outside } = splitFences(text);
  const slugs = new Map();
  const headings = [];

  for (const line of outside.split('\n')) {
    const heading = /^ {0,3}(#{1,6})\s+(.*)$/.exec(line);

    if (heading === null) continue;

    const base = slugify(plainHeadingText(heading[2]));

    if (base === '') continue;

    let slug = base;
    let suffix = slugs.get(base) ?? 0;

    while (slugs.has(slug)) {
      suffix += 1;
      slug = `${base}-${suffix}`;
    }

    slugs.set(base, suffix);
    slugs.set(slug, 0);
    headings.push({ slug, occurrence: suffix });
  }

  return { slugs, headings };
}

/** Strip remaining inline heading markup; code-span content stays. */
function plainHeadingText(text) {
  let plain = '';
  let inCode = false;

  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];

    if (character === '`') {
      inCode = !inCode;
      continue;
    }

    if (!inCode && character === '\\' && index + 1 < text.length) {
      plain += text[index + 1];
      index += 1;
      continue;
    }

    plain += character;
  }

  return plain;
}

/** Resolve one fragment slug against duplicate-aware positions. */
export function headingMatch(headingIndex, fragment) {
  const slug = decodeURIComponent(fragment);

  return headingIndex.slugs.has(slug);
}

/**
 * Validate inline links of one document against the tracked Markdown scope.
 * Fenced examples are excluded. Skipped targets are counted and returned so
 * the report never silently swallows them.
 */
export function checkRelativeLinks(text, file, scope) {
  const findings = [];
  const { outside } = splitFences(text);
  const headingIndex = collectHeadings(text);
  const counts = { checked: 0, skippedExternal: 0, skippedTargetsOutsideScope: 0 };

  const link = /!?\[([^\]]*)\]\(\s*(<[^>]*>|[^)\s]+)[^)]*\)/g;

  for (const match of outside.matchAll(link)) {
    let target = match[2];

    if (target.startsWith('<') && target.endsWith('>')) {
      target = target.slice(1, -1);
    }

    if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(target)) {
      counts.skippedExternal += 1;
      continue;
    }

    if (match[0].startsWith('!')) {
      counts.skippedTargetsOutsideScope += 1;
      continue;
    }

    const hash = target.indexOf('#');
    const fragment = hash === -1 ? '' : target.slice(hash + 1);
    const filePart = hash === -1 ? target : target.slice(0, hash);

    if (filePart !== '') {
      if (!/\.(?:md|markdown)$/i.test(filePart)) {
        counts.skippedTargetsOutsideScope += 1;
        continue;
      }

      const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(file), filePart));

      if (resolved.startsWith('..') || path.posix.isAbsolute(filePart)) {
        findings.push({ kind: 'escaping-link-target', file, target, resolved });
        continue;
      }

      if (!scope.has(resolved)) {
        findings.push({ kind: 'unexpected-markdown-target', file, target, resolved });
        continue;
      }

      if (fragment === '') {
        counts.checked += 1;
        continue;
      }

      if (!headingMatch(collectHeadings(scope.get(resolved)), fragment)) {
        findings.push({ kind: 'broken-heading-anchor', file, target, fragment, resolved });
        continue;
      }

      counts.checked += 1;
      continue;
    }

    if (fragment !== '' && headingMatch(headingIndex, fragment)) {
      counts.checked += 1;
      continue;
    }

    findings.push({ kind: 'broken-heading-anchor', file, target, fragment });
  }

  return { findings, counts };
}

/* -------------------------------------------------------------------------- */
/* aggregation (pure)                                                         */
/* -------------------------------------------------------------------------- */

/** Validate the built registry export shape at the import boundary. */
export async function readBuiltRegistry(projectRoot) {
  const registryPath = path.join(projectRoot, REGISTRY_RELATIVE);

  if (!existsSync(registryPath)) return null;

  const module = await import(pathToFileURL(registryPath).href);
  const providers = module.SUPPORTED_PROVIDERS;

  if (!Array.isArray(providers) || providers.length === 0) return null;

  const ids = [];

  for (const provider of providers) {
    if (Object.prototype.toString.call(provider) !== '[object String]' || provider === '') return null;

    ids.push(provider);
  }

  return ids;
}

/**
 * Run every documentation contract check over one document set. Pure: no
 * filesystem, process, or network access. `files` maps the repo-relative
 * scope paths to text; `registry` is the built provider order; `policy` is
 * the frozen per-provider algorithm map.
 */
export function runDocsContract(files, registry, policy) {
  const findings = [];

  for (const docFile of DOC_SCOPE) {
    if (!Object.hasOwn(files, docFile)) {
      findings.push({ kind: 'missing-doc', file: docFile });
    }
  }

  findings.push(...checkPolicyRegistrySync(registry, policy));

  for (const docFile of DOC_SCOPE) {
    if (!Object.hasOwn(files, docFile)) continue;

    findings.push(...checkGlobalClaims(files[docFile], docFile));
  }

  if (Object.hasOwn(files, 'README.md')) {
    const parsed = parseOverviewRegion(files['README.md'], README_COLUMNS, 'README.md');

    if (parsed.ok) {
      findings.push(...checkOverview(parsed.table, registry, policy));
    } else {
      findings.push(...parsed.findings);
    }
  }

  if (Object.hasOwn(files, 'docs/providers.md')) {
    const parsed = parseOverviewRegion(files['docs/providers.md'], GUIDE_COLUMNS, 'docs/providers.md');

    if (parsed.ok) {
      findings.push(...checkOverview(parsed.table, registry, policy));
    } else {
      findings.push(...parsed.findings);
    }
  }

  const scope = new Map();

  for (const docFile of DOC_SCOPE) {
    if (Object.hasOwn(files, docFile)) {
      scope.set(docFile, files[docFile]);
    }
  }

  const linkTotals = { checked: 0, skippedExternal: 0, skippedTargetsOutsideScope: 0 };

  for (const docFile of DOC_SCOPE) {
    if (!scope.has(docFile)) continue;

    const linkReport = checkRelativeLinks(files[docFile], docFile, scope);

    findings.push(...linkReport.findings);

    linkTotals.checked += linkReport.counts.checked;
    linkTotals.skippedExternal += linkReport.counts.skippedExternal;
    linkTotals.skippedTargetsOutsideScope += linkReport.counts.skippedTargetsOutsideScope;
  }

  return { findings, linkTotals };
}

/* -------------------------------------------------------------------------- */
/* guarded CLI                                                                */
/* -------------------------------------------------------------------------- */

const invokedDirectly = process.argv[1] !== undefined
  && import.meta.url === pathToFileURL(process.argv[1]).href;

/** Guarded CLI entry: either `--json` or no argument prints one JSON report. */
async function main() {
  for (const argument of process.argv.slice(2)) {
    if (argument !== '--json') {
      process.stderr.write(`docs-contract: unknown argument ${JSON.stringify(argument)}\n`);

      process.exitCode = EXIT.USAGE;

      return;
    }
  }

  const projectRoot = path.resolve(import.meta.dirname, '..', '..');
  const registry = await readBuiltRegistry(projectRoot);

  if (registry === null) {
    console.log(JSON.stringify({
      schemaVersion: 1,
      phase: 'phase-10 documentation contract',
      status: 'blocked',
      exit: EXIT.BLOCKED,
      reason: `missing or invalid built registry at ${REGISTRY_RELATIVE}; run npm run build first`,
      findings: [],
    }, null, 2));

    process.exitCode = EXIT.BLOCKED;

    return;
  }

  const files = {};

  for (const docFile of DOC_SCOPE) {
    const docPath = path.join(projectRoot, docFile);

    if (!existsSync(docPath)) continue;

    files[docFile] = readFileSync(docPath, 'utf8');
  }

  const report = runDocsContract(files, registry, ALGORITHM_POLICY);
  const status = report.findings.length > 0 ? 'fail' : 'pass';

  console.log(JSON.stringify({
    schemaVersion: 1,
    phase: 'phase-10 documentation contract',
    status,
    exit: status === 'pass' ? EXIT.PASS : EXIT.RED,
    summary: {
      findings: report.findings.length,
      findingKinds: findingKinds(report.findings),
      findingFiles: findingFiles(report.findings),
      links: report.linkTotals,
      builtRegistryOrder: registry,
    },
    findings: report.findings,
  }, null, 2));

  process.exitCode = status === 'pass' ? EXIT.PASS : EXIT.RED;
}

function findingKinds(findings) {
  const kinds = new Set();

  for (const finding of findings) {
    kinds.add(finding.kind);
  }

  return [...kinds].sort();
}

function findingFiles(findings) {
  const names = new Set();

  for (const finding of findings) {
    const findingIsObject = Object.prototype.toString.call(finding) === '[object Object]';

    if (findingIsObject && Object.hasOwn(finding, 'file')) {
      names.add(finding.file);
    }
  }

  return [...names].sort();
}

if (invokedDirectly) {
  await main();
}
