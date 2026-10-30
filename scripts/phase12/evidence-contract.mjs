#!/usr/bin/env node
/**
 * Standalone offline consistency checker for Hooklatch 21-provider verification evidence.
 *
 * Validates docs/verification-evidence.json and docs/verification-evidence.md against
 * the frozen Phase 12 release preparation contract:
 *  - Exact 21 provider inventory and built registry order.
 *  - Algorithm policy and enum consistency across all providers.
 *  - Strict separation of evidence classes:
 *      * 4 pinned vendor SDK comparisons (49 cases = 41 agreements + 8 divergences)
 *      * 2 documentation-only probes (8 probes = 4 vercel + 4 fal)
 *      * 15 providers explicitly not-compared (no alias extrapolation)
 *      * Historical totals: 57 cases, 41 agreements, 8 divergences, 8 docs probes, 0 mismatches
 *      * Sandbox delivery status must be 'not-run' for all 21 providers
 *  - Required provenance: base SHA, live GitHub CI run 40650684406, and 5 historical receipt hashes.
 *  - Rejection of historical-as-current claims (testedHead !== baseSha).
 *  - Full agreement between public Markdown table and JSON data.
 *
 * Exit codes:
 *   0  PASS    - all evidence invariants verified
 *   1  RED     - contract findings exist
 *   2  USAGE   - invalid CLI invocation
 *   3  BLOCKED - required documentation file absent
 */

import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

export const EXIT = Object.freeze({
  PASS: 0,
  RED: 1,
  USAGE: 2,
  BLOCKED: 3,
});

export const FROZEN_BASE_SHA = 'baa8a7427fbed42404f97d3b66c68c160ff1555f';
export const HISTORICAL_SDK_TESTED_HEAD = '1747694b73b1c61254d99ad3217768650654d410';
export const CI_RUN_ID = 40650684406;
export const CI_URL = 'https://github.com/Its-amanjha/Hooklatch/actions/runs/40650684406';

export const HISTORICAL_RECEIPT_HASHES = Object.freeze({
  'coordinator-conformance-acceptance.json': '453b51cabba98a82def7db0bc25474b6a605917843484c3a37066dc217ef8c16',
  'coordinator-conformance-node22-results.json': '24ce3d5cf50448146927a1437ddba40f86bd17b17dc538005e143c9364a138d3',
  'coordinator-conformance-node24-results.json': '9e2ac4bb4c3a348e27023ecfb94ea608ce632c0e56466d7f2fedb57df794ca04',
  'compatibility-acceptance-baa8a74.json': '7222e09211d0e0cf9f7f096082105d5bbc77c101fe1b1b28f614a3fe9670ac64',
  'ci-success-2026-10-29.json': 'bb2b31d15bd214c8374ac9610420233fb2265a2a2151034a2f7e1f6d2d5aec8d',
});

/** Exact 21 providers in built registry order. */
export const REGISTRY_PROVIDERS = Object.freeze([
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
]);

/** Frozen provider algorithm policies. */
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

export const PINNED_SDK_POLICIES = Object.freeze({
  'standard-webhooks': {
    package: 'standardwebhooks',
    version: '1.1.1',
    casesCount: 16,
    agreements: 14,
    divergences: 2,
    docsProbes: 0,
  },
  paddle: {
    package: '@paddle/paddle-node-sdk',
    version: '3.10.0',
    casesCount: 14,
    agreements: 11,
    divergences: 3,
    docsProbes: 0,
  },
  sanity: {
    package: '@sanity/webhook',
    version: '4.0.4',
    casesCount: 9,
    agreements: 7,
    divergences: 2,
    docsProbes: 0,
  },
  linear: {
    package: '@linear/sdk',
    version: '99.0.0',
    casesCount: 10,
    agreements: 9,
    divergences: 1,
    docsProbes: 0,
  },
});

export const DOCS_PROBE_PROVIDERS = Object.freeze(['vercel', 'fal']);

/** Parse the 21-provider evidence table from Markdown. */
export function parseMarkdownEvidenceTable(markdownContent) {
  const lines = markdownContent.split('\n');
  const tableRows = [];
  let inTable = false;

  for (const rawLine of lines) {
    const line = rawLine.trim();

    if (!inTable) {
      if (line.startsWith('|') && line.includes('Provider') && line.includes('Algorithm')) {
        inTable = true;
      }

      continue;
    }

    if (!line.startsWith('|')) {
      if (tableRows.length > 0) {
        break;
      }

      continue;
    }

    if (line.includes('---|') || line.includes(':---|') || line.includes('---:|')) {
      continue;
    }

    const cells = line
      .split('|')
      .slice(1, -1)
      .map((c) => c.trim());

    if (cells.length >= 7) {
      const rawProvider = cells[0].replace(/`/g, '');
      const algorithm = cells[1];
      const fixtures = cells[2];
      const sdkComparison = cells[3];
      const caseCounts = cells[4];
      const runtimeQualification = cells[5];
      const sandboxDelivery = cells[6];

      tableRows.push({
        provider: rawProvider,
        algorithm,
        fixtures,
        sdkComparison,
        caseCounts,
        runtimeQualification,
        sandboxDelivery,
      });
    }
  }

  return tableRows;
}

function isPlainObject(value) {
  return value !== null && Object.prototype.toString.call(value) === '[object Object]';
}

/** Validate evidence document against contract invariants. */
export function validateEvidence(evidence, markdownContent) {
  const findings = [];

  if (!isPlainObject(evidence)) {
    return [{ rule: 'schema-root', message: 'Evidence document must be a non-null object' }];
  }

  if (evidence.schemaVersion !== 1) {
    findings.push({
      rule: 'schema-version',
      message: `Expected schemaVersion 1, found ${evidence.schemaVersion}`,
    });
  }

  if (evidence.baseSha !== FROZEN_BASE_SHA) {
    findings.push({
      rule: 'base-sha-mismatch',
      message: `Expected baseSha ${FROZEN_BASE_SHA}, found ${evidence.baseSha}`,
    });
  }

  const ci = evidence.provenance?.ci;

  if (!ci || ci.runId !== CI_RUN_ID || ci.head !== FROZEN_BASE_SHA || ci.conclusion !== 'success') {
    findings.push({
      rule: 'ci-provenance-invalid',
      message: `CI provenance mismatch: runId=${ci?.runId}, head=${ci?.head}, conclusion=${ci?.conclusion}`,
    });
  }

  const receipts = evidence.provenance?.historicalEvaluationReceipts?.receipts;

  if (!isPlainObject(receipts)) {
    findings.push({
      rule: 'receipt-hashes-missing',
      message: 'Missing historicalEvaluationReceipts receipts map',
    });
  } else {
    for (const [fileName, expectedHash] of Object.entries(HISTORICAL_RECEIPT_HASHES)) {
      if (receipts[fileName] !== expectedHash) {
        findings.push({
          rule: 'receipt-hash-invalid',
          message: `Receipt ${fileName} hash mismatch. Expected ${expectedHash}, found ${receipts[fileName]}`,
        });
      }
    }
  }

  const histSdk = evidence.provenance?.historicalSdkEvaluation;

  if (!isPlainObject(histSdk)) {
    findings.push({
      rule: 'historical-sdk-missing',
      message: 'Missing provenance.historicalSdkEvaluation block',
    });
  } else {
    if (histSdk.testedHead !== HISTORICAL_SDK_TESTED_HEAD) {
      findings.push({
        rule: 'historical-tested-head-mismatch',
        message: `Historical SDK testedHead must be ${HISTORICAL_SDK_TESTED_HEAD}, found ${histSdk.testedHead}`,
      });
    }

    if (histSdk.testedHead === evidence.baseSha) {
      findings.push({
        rule: 'historical-tested-head-current-sha',
        message: 'Historical SDK evaluation must not claim current baseSha as tested head',
      });
    }

    if (histSdk.totalCases !== 57 || histSdk.agreements !== 41 || histSdk.divergences !== 8 || histSdk.docsProbes !== 8) {
      findings.push({
        rule: 'historical-cases-mismatch',
        message: `Expected 57 total cases (41 agreements, 8 divergences, 8 docs probes), found: ${JSON.stringify(histSdk)}`,
      });
    }

    if (histSdk.agreements + histSdk.divergences + histSdk.docsProbes !== histSdk.totalCases) {
      findings.push({
        rule: 'historical-cases-arithmetic',
        message: 'Sum of agreements, divergences, and docsProbes does not equal totalCases',
      });
    }

    if (histSdk.unexpectedMismatches !== 0) {
      findings.push({
        rule: 'unexpected-mismatches-nonzero',
        message: `Historical SDK unexpectedMismatches must be 0, found ${histSdk.unexpectedMismatches}`,
      });
    }
  }

  const totals = evidence.provenance?.qualificationTotals;

  if (!totals || totals.providersCount !== 21 || totals.workersProviderCases !== 725) {
    findings.push({
      rule: 'qualification-totals-invalid',
      message: `Invalid qualificationTotals: providersCount=${totals?.providersCount}, workersProviderCases=${totals?.workersProviderCases}`,
    });
  }

  const providers = evidence.providers;

  if (!Array.isArray(providers)) {
    findings.push({
      rule: 'providers-not-array',
      message: 'evidence.providers must be an array',
    });

    return findings;
  }

  if (providers.length !== 21) {
    findings.push({
      rule: 'provider-count-mismatch',
      message: `Expected exactly 21 providers, found ${providers.length}`,
    });
  }

  let totalSdkCases = 0;
  let totalAgreements = 0;
  let totalDivergences = 0;
  let totalDocsProbes = 0;
  let totalUnexpectedMismatches = 0;

  for (let index = 0; index < providers.length; index++) {
    const p = providers[index];
    const expectedId = REGISTRY_PROVIDERS[index];

    if (p.provider !== expectedId) {
      findings.push({
        rule: 'provider-order-mismatch',
        message: `Provider at index ${index} must be '${expectedId}', found '${p.provider}'`,
      });
    }

    if (p.registryOrder !== index + 1) {
      findings.push({
        rule: 'registry-order-mismatch',
        message: `Provider ${p.provider} registryOrder must be ${index + 1}, found ${p.registryOrder}`,
      });
    }

    const expectedAlgo = ALGORITHM_POLICY[p.provider];

    if (p.algorithm !== expectedAlgo) {
      findings.push({
        rule: 'algorithm-mismatch',
        message: `Provider ${p.provider} algorithm must be '${expectedAlgo}', found '${p.algorithm}'`,
      });
    }

    if (p.sandboxDelivery?.status !== 'not-run') {
      findings.push({
        rule: 'sandbox-status-not-run',
        message: `Provider ${p.provider} sandboxDelivery status must be 'not-run', found '${p.sandboxDelivery?.status}'`,
      });
    }

    if (p.runtimeQualification?.status !== 'qualified-offline') {
      findings.push({
        rule: 'runtime-status-invalid',
        message: `Provider ${p.provider} runtimeQualification status must be 'qualified-offline'`,
      });
    }

    const fixture = p.fixtureCases;

    if (!fixture || fixture.total !== fixture.reference + fixture.local) {
      findings.push({
        rule: 'fixture-cases-arithmetic',
        message: `Provider ${p.provider} fixture total must equal reference + local`,
      });
    }

    const sdk = p.sdkComparison;

    if (PINNED_SDK_POLICIES[p.provider]) {
      const policy = PINNED_SDK_POLICIES[p.provider];

      if (sdk?.status !== 'compared') {
        findings.push({
          rule: 'sdk-status-compared',
          message: `Pinned SDK provider ${p.provider} must have status 'compared', found '${sdk?.status}'`,
        });
      }

      if (sdk?.package !== policy.package || sdk?.version !== policy.version) {
        findings.push({
          rule: 'sdk-package-version-mismatch',
          message: `Pinned SDK provider ${p.provider} package/version mismatch`,
        });
      }

      if (
        sdk?.casesCount !== policy.casesCount ||
        sdk?.agreements !== policy.agreements ||
        sdk?.divergences !== policy.divergences ||
        sdk?.docsProbes !== policy.docsProbes
      ) {
        findings.push({
          rule: 'sdk-counts-mismatch',
          message: `Pinned SDK provider ${p.provider} counts mismatch policy`,
        });
      }

      if (sdk?.unexpectedMismatches !== 0) {
        findings.push({
          rule: 'sdk-mismatches-nonzero',
          message: `Pinned SDK provider ${p.provider} unexpectedMismatches must be 0`,
        });
      }

      if (sdk?.testedHead !== HISTORICAL_SDK_TESTED_HEAD) {
        findings.push({
          rule: 'sdk-tested-head-mismatch',
          message: `Pinned SDK provider ${p.provider} testedHead must be ${HISTORICAL_SDK_TESTED_HEAD}`,
        });
      }

      totalSdkCases += sdk?.casesCount ?? 0;
      totalAgreements += sdk?.agreements ?? 0;
      totalDivergences += sdk?.divergences ?? 0;
      totalDocsProbes += sdk?.docsProbes ?? 0;
      totalUnexpectedMismatches += sdk?.unexpectedMismatches ?? 0;
    } else if (DOCS_PROBE_PROVIDERS.includes(p.provider)) {
      if (sdk?.status !== 'docs-only') {
        findings.push({
          rule: 'docs-probe-status',
          message: `Docs-only provider ${p.provider} status must be 'docs-only', found '${sdk?.status}'`,
        });
      }

      if (sdk?.casesCount !== 4 || sdk?.docsProbes !== 4 || sdk?.agreements !== 0 || sdk?.divergences !== 0) {
        findings.push({
          rule: 'docs-probe-counts',
          message: `Docs-only provider ${p.provider} must report 4 docs probes and 0 agreements/divergences`,
        });
      }

      totalSdkCases += sdk?.casesCount ?? 0;
      totalDocsProbes += sdk?.docsProbes ?? 0;
    } else {
      if (sdk?.status !== 'not-compared') {
        findings.push({
          rule: 'unauthorized-sdk-comparison',
          message: `Provider ${p.provider} must be explicitly 'not-compared' (no alias extrapolation), found '${sdk?.status}'`,
        });
      }

      if (sdk?.package !== null || sdk?.version !== null || sdk?.casesCount !== null) {
        findings.push({
          rule: 'uncompared-sdk-fields-present',
          message: `Provider ${p.provider} is not-compared but carries package/version/caseCounts`,
        });
      }
    }
  }

  if (totalSdkCases !== 57 || totalAgreements !== 41 || totalDivergences !== 8 || totalDocsProbes !== 8) {
    findings.push({
      rule: 'aggregate-sdk-totals-mismatch',
      message: `Aggregate SDK cases must be 57 (41 agreements, 8 divergences, 8 docs probes). Computed: cases=${totalSdkCases}, agreements=${totalAgreements}, divergences=${totalDivergences}, docsProbes=${totalDocsProbes}`,
    });
  }

  if (totalUnexpectedMismatches !== 0) {
    findings.push({
      rule: 'aggregate-unexpected-mismatches-nonzero',
      message: `Aggregate unexpected mismatches must be 0, found ${totalUnexpectedMismatches}`,
    });
  }

  if (markdownContent) {
    const mdRows = parseMarkdownEvidenceTable(markdownContent);

    if (mdRows.length !== 21) {
      findings.push({
        rule: 'markdown-row-count-mismatch',
        message: `Markdown table must contain exactly 21 rows, found ${mdRows.length}`,
      });
    }

    for (let i = 0; i < Math.min(mdRows.length, providers.length); i++) {
      const mdRow = mdRows[i];
      const jsonRow = providers[i];

      if (mdRow.provider !== jsonRow.provider) {
        findings.push({
          rule: 'markdown-json-disagreement',
          message: `Row ${i + 1} provider mismatch: Markdown has '${mdRow.provider}', JSON has '${jsonRow.provider}'`,
        });
      }

      if (mdRow.algorithm !== jsonRow.algorithm) {
        findings.push({
          rule: 'markdown-json-disagreement',
          message: `Provider ${jsonRow.provider} algorithm mismatch: Markdown has '${mdRow.algorithm}', JSON has '${jsonRow.algorithm}'`,
        });
      }

      if (mdRow.sandboxDelivery !== 'not-run') {
        findings.push({
          rule: 'markdown-sandbox-not-run',
          message: `Markdown row for ${jsonRow.provider} must state sandbox delivery 'not-run', found '${mdRow.sandboxDelivery}'`,
        });
      }

      if (jsonRow.sdkComparison.status === 'not-compared' && !mdRow.sdkComparison.includes('not-compared')) {
        findings.push({
          rule: 'markdown-json-disagreement',
          message: `Provider ${jsonRow.provider} is not-compared in JSON but not in Markdown: '${mdRow.sdkComparison}'`,
        });
      }
    }
  }

  return findings;
}

/** Execute internal negative controls to verify that mutant inputs are rejected. */
export function runSelfTest(baseEvidence, baseMarkdown) {
  const tests = [
    {
      name: 'deliberate-wrong-count',
      expectedRule: 'provider-count-mismatch',
      mutate: (data) => {
        data.providers = data.providers.slice(0, 20);
      },
    },
    {
      name: 'missing-provider-or-order',
      expectedRule: 'provider-order-mismatch',
      mutate: (data) => {
        data.providers[0].provider = 'github';
        data.providers[1].provider = 'stripe';
      },
    },
    {
      name: 'false-live-status',
      expectedRule: 'sandbox-status-not-run',
      mutate: (data) => {
        data.providers[0].sandboxDelivery.status = 'live-verified';
      },
    },
    {
      name: 'historical-as-current-sha',
      expectedRule: 'historical-tested-head-current-sha',
      mutate: (data) => {
        data.provenance.historicalSdkEvaluation.testedHead = data.baseSha;
      },
    },
    {
      name: 'wrong-historical-case-totals',
      expectedRule: 'historical-cases-mismatch',
      mutate: (data) => {
        data.provenance.historicalSdkEvaluation.totalCases = 56;
      },
    },
    {
      name: 'unexpected-mismatches-nonzero',
      expectedRule: 'unexpected-mismatches-nonzero',
      mutate: (data) => {
        data.provenance.historicalSdkEvaluation.unexpectedMismatches = 1;
      },
    },
    {
      name: 'missing-receipt-hash',
      expectedRule: 'receipt-hash-invalid',
      mutate: (data) => {
        data.provenance.historicalEvaluationReceipts.receipts['ci-success-2026-10-29.json'] = '0000000000';
      },
    },
    {
      name: 'algorithm-mismatch',
      expectedRule: 'algorithm-mismatch',
      mutate: (data) => {
        data.providers[0].algorithm = 'RSA-SHA256';
      },
    },
    {
      name: 'extrapolated-alias',
      expectedRule: 'unauthorized-sdk-comparison',
      mutate: (data) => {
        data.providers[4].sdkComparison.status = 'compared';
        data.providers[4].sdkComparison.package = 'standardwebhooks';
      },
    },
    {
      name: 'markdown-disagreement',
      expectedRule: 'markdown-json-disagreement',
      mutate: (_data, md) => {
        return md.replace('| `stripe` | HMAC-SHA256', '| `stripe` | HMAC-SHA1');
      },
    },
  ];

  const results = [];

  for (const t of tests) {
    const clone = JSON.parse(JSON.stringify(baseEvidence));
    let testMd = baseMarkdown;

    if (t.mutate.length === 2) {
      testMd = t.mutate(clone, testMd);
    } else {
      t.mutate(clone);
    }

    const findings = validateEvidence(clone, testMd);
    const matched = findings.some((f) => f.rule === t.expectedRule);

    results.push({
      test: t.name,
      expectedRule: t.expectedRule,
      passed: matched,
      findingsCount: findings.length,
      sampleMessage: findings[0]?.message,
    });
  }

  const allPassed = results.every((r) => r.passed);

  return {
    allPassed,
    totalTests: results.length,
    results,
  };
}

function printUsage() {
  process.stdout.write(
    'Usage: node scripts/phase12/evidence-contract.mjs [options]\n\n' +
      'Options:\n' +
      '  --help       Show this help message and exit (0)\n' +
      '  --self-test  Run negative mutation controls and report results (0 on success)\n' +
      '  --check      Validate docs/verification-evidence.{json,md} (default mode)\n'
  );
}

function resolveWorkspacePaths() {
  const scriptDir = path.dirname(fileURLToPath(import.meta.url));
  const rootDir = path.resolve(scriptDir, '..', '..');

  return {
    rootDir,
    jsonPath: path.join(rootDir, 'docs', 'verification-evidence.json'),
    mdPath: path.join(rootDir, 'docs', 'verification-evidence.md'),
  };
}

export function main(argv = process.argv.slice(2)) {
  const args = argv;

  if (args.includes('--help') || args.includes('-h')) {
    printUsage();

    return EXIT.PASS;
  }

  const { jsonPath, mdPath } = resolveWorkspacePaths();

  if (!existsSync(jsonPath) || !existsSync(mdPath)) {
    process.stderr.write(
      `BLOCKED: Required evidence files missing. Ensure ${jsonPath} and ${mdPath} exist.\n`
    );

    return EXIT.BLOCKED;
  }

  let evidence;
  let markdown;

  try {
    evidence = JSON.parse(readFileSync(jsonPath, 'utf8'));
    markdown = readFileSync(mdPath, 'utf8');
  } catch (err) {
    process.stderr.write(`BLOCKED: Failed to read or parse evidence documents: ${err.message}\n`);

    return EXIT.BLOCKED;
  }

  if (args.includes('--self-test')) {
    const selfTest = runSelfTest(evidence, markdown);

    process.stdout.write(JSON.stringify(selfTest, null, 2) + '\n');

    return selfTest.allPassed ? EXIT.PASS : EXIT.RED;
  }

  if (args.length > 0 && !args.includes('--check')) {
    process.stderr.write(`USAGE: Unknown argument '${args[0]}'. Use --help for usage.\n`);

    return EXIT.USAGE;
  }

  const findings = validateEvidence(evidence, markdown);

  if (findings.length > 0) {
    process.stdout.write(
      JSON.stringify(
        {
          status: 'RED',
          exitCode: EXIT.RED,
          findingsCount: findings.length,
          findings,
        },
        null,
        2
      ) + '\n'
    );

    return EXIT.RED;
  }

  process.stdout.write(
    JSON.stringify(
      {
        status: 'PASS',
        exitCode: EXIT.PASS,
        providersCount: evidence.providers.length,
        baseSha: evidence.baseSha,
        ciRunId: evidence.provenance.ci.runId,
        historicalSdkTotalCases: evidence.provenance.historicalSdkEvaluation.totalCases,
        allSandboxNotRun: true,
      },
      null,
      2
    ) + '\n'
  );

  return EXIT.PASS;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const exitCode = main(process.argv.slice(2));

  process.exit(exitCode);
}
