# Contributing

Thank you for your interest in improving Hooklatch. This guide covers the
development workflow, commands, and requirements for protocol tests.

## Prerequisites

- Node.js >= 22
- npm >= 10

## Setup

```bash
npm install
```

## Commands

| Command | Purpose |
|---------|---------|
| `npm run verify` | Run all local release gates in order; stop on first failure |
| `npm run build` | Compile portable SDK and Node-only CLI to `dist/` |
| `npm run dev` | Watch the portable compiler project; rebuild CLI with `npm run build` |
| `npm run typecheck` | Type-check without emitting |
| `npm run typecheck:workers` | Type-check the real-workerd test Worker |
| `npm run typecheck:examples` | Check examples against built package types |
| `npm test` | Run the Jest suite (offline, deterministic) |
| `npm run test:coverage` | Run tests with coverage |
| `npm run lint` | Run ESLint and anti-slop checks |
| `npm run lint:eslint` | Run the existing ESLint checks |
| `npm run lint:anti-slop` | Run vendored anti-slop checks on source, tests, scripts and examples |
| `npm run test:workers` | Run the Workers runtime smoke harness |
| `npm run test:package` | Pack and install offline without optional frameworks |
| `npm run test:templates` | Generate and strictly type-check all 24 CLI handlers against the packed package (build first) |

All checks must pass before submitting a change. Do not commit code that
skips or weakens tests.

## Project layout

- `src/` — core implementation (types, errors, internal helpers, providers)
- `tests/` — Jest test suites
- `examples/` — runnable TypeScript examples
- `scripts/` — maintenance and smoke-test scripts

The core normalizes headers, parses provider signatures, verifies exact bytes,
then checks signed timestamps. Payload parsing stays with the caller. Framework
adapters, pure diagnostics, and the Node-only CLI have separate entry points.

## Writing tests

Tests are **offline and deterministic**. Requirements:

- Use fixed clocks — inject `now` into `VerifyOptions` rather than relying on
  wall-clock time.
- Use synthetic data — never call live provider endpoints or embed real
  secrets.
- Use `.js` relative import extensions in TypeScript files.
- Cover exact-byte preservation, tampering, malformed headers, missing
  signatures, multiple signatures, secret rotation, timestamp boundaries,
  non-JSON bodies, and body reuse.

## Adding a provider

Each provider is a self-contained descriptor under `src/providers/<provider>.ts`
that implements the `ProviderDescriptor` interface from
`src/internal/provider.ts`:

1. `decodeSecret(secret)` — validate and decode the secret to the raw HMAC
   key bytes. Throw `HooklatchError('invalid-secret')` on invalid input.
2. `parse(headers, rawBody)` — extract signatures, build the signed content,
   and return metadata. Return `FailureDetails` on malformed input; freshness
   and HMAC checks belong to the core.

Provider-specific rules:

- **Stripe** — signs `timestamp.body`; uses the literal secret string as the
  HMAC key; signature is hex-encoded; `v1` may repeat, but duplicate `t` is rejected.
- **GitHub** — signs the body only; `X-Hub-Signature-256` is `sha256=<hex>`;
  no signed timestamp.
- **Shopify** — signs the body only; Base64-encoded HMAC; no signed
  timestamp.
- **Standard Webhooks** — signs `id.timestamp.body`; strips the `whsec_`
  prefix and Base64-decodes the key; signatures are space-delimited
  `v1,<base64>` tokens.

Before advertising provider support:

- Add deterministic test vectors (published reference vectors preferred;
  locally generated anchors must be labelled as such).
- Cross-check against official provider documentation or reference
  implementations.
- Record source links in the provider file header.

## Code style

- TypeScript strict mode; no `any` without justification.
- ESM only — `.js` extensions in relative imports.
- No runtime dependencies in the core.
- Match existing formatting and naming conventions.

## Pull requests

1. Fork and create a feature branch.
2. Make your change with tests.
3. Run `npm run typecheck`, `npm run lint`, and `npm test`.
4. Describe what changed and why in the PR body.
5. Note any limitations or follow-ups.

## Reporting vulnerabilities

See `SECURITY.md`.

## Preparing a release

Run `npm ci` and `npm run verify` before inspecting `npm pack --dry-run`.
Packing alone does not build the package or guarantee that `dist/` exists.
Check that every exported entry point and the CLI are included, and that local
notes, credentials, tests, and development tools are excluded. Confirm a private
security-reporting channel and the supported-version policy before publishing.
Publication, registry access, and provenance configuration are separate maintainer
operations; passing CI does not publish a release.

## Source and history notes

The idea came from the maintainer's refinements of a general discussion on X.
The generated implementation brief contained Hookflo/Tern identifiers; those
were replaced with Hooklatch. This project is not affiliated with Hookflo/Tern.
A bounded review on 2026-10-19 compared Hooklatch at `544b09f` with
[Tern at its pinned revision](https://github.com/Hookflo/tern/tree/3739224566f1080e7ebcdf57e1e145fcfde0e0c1)
and found no distinctive copied implementation block or documentation passage.
That review does not prove independent authorship or establish rights.

Published reference vectors retain their original source links in fixtures,
tests, and the README. Standard Webhooks' pinned repository has an Apache-2.0
root license and a nested [MIT notice attributed to Svix, copyright 2023](https://github.com/standard-webhooks/standard-webhooks/blob/7537d2a2d3d52d8f2e0ecd12527af4a9307fd81b/libraries/LICENSE).
These are source metadata observations, not a determination of rights to test
values. Synthetic fixtures must remain distinguishable from published vectors.

The first 57 commits were reconstructed from a completed snapshot on
2026-10-18. At the owner's request, their dates span October 2–18, excluding
October 8, 11, and 15. These dates do not establish when development occurred,
and intermediate commits were not independently verified. Subsequent work uses
actual timestamps. Private coordination files were removed from public history;
some original commit positions and messages remain despite empty changes.
