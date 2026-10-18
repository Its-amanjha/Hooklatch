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
| `npm run build` | Compile TypeScript to `dist/` |
| `npm run dev` | Watch-compile TypeScript |
| `npm run typecheck` | Type-check without emitting |
| `npm run typecheck:workers` | Type-check the real-workerd test Worker |
| `npm run typecheck:examples` | Check examples against built package types |
| `npm test` | Run the Jest suite (offline, deterministic) |
| `npm run test:coverage` | Run tests with coverage |
| `npm run lint` | Run ESLint on `src`, `tests`, `scripts` |
| `npm run test:workers` | Run the Workers runtime smoke harness |
| `npm run test:package` | Pack and install offline without optional frameworks |

All checks must pass before submitting a change. Do not commit code that
skips or weakens tests.

## Project layout

- `src/` — core implementation (types, errors, internal helpers, providers)
- `tests/` — Jest test suites
- `examples/` — runnable TypeScript examples
- `scripts/` — maintenance and smoke-test scripts

See `ARCHITECTURE.md` for the full structure.

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
