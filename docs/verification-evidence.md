# Verification and conformance evidence

Hooklatch maintains an explicit, verifiable qualification matrix covering all 21 supported webhook providers in built registry order. This document details the exact evidentiary foundation for Hooklatch's verification behavior, distinguishing externally sourced reference vectors, synthetic test cases, pinned vendor SDK comparisons, documentation-based algorithm probes, local runtime qualification, and live sandbox status.

## Evidence classification

The matrix separates these evidence classes:

1. **Published reference vectors**: External test vectors published by vendors in their official documentation or reference test suites. These vectors provide fixed inputs, secrets, timestamps, and expected signatures without Hooklatch synthesis.
2. **Local synthetic fixtures**: Deterministic test fixtures generated locally with `node:crypto`. These exercise edge cases, secret rotation, timestamp expiry, header whitespace variations, malformed parameters, and body tampering across all 21 providers without live network calls.
3. **Pinned vendor SDK comparison (historical offline qualification)**: Differential evaluation against four official vendor SDK packages executed under frozen offline qualification at historical commit `1747694b73b1c61254d99ad3217768650654d410` (recorded execution 2026-10-24 on Node.js v22.23.4 and v24.15.0).
   > [!IMPORTANT]
   > Historical SDK qualification results represent frozen historical inputs and are **not** a fresh rerun on the current commit (`baa8a7427fbed42404f97d3b66c68c160ff1555f`). Hooklatch core maintains zero runtime dependencies and does not install vendor SDKs in production or CI environments.
4. **Documentation-only probes**: For providers that do not distribute a standalone Node.js verification SDK (Vercel and fal), verification recipes are probed against published vendor technical specifications.
5. **Local runtime and framework qualification**: Offline execution across supported runtime engines (Node.js >= 22.0.0, Cloudflare Workers `workerd`), full framework adapters (Next.js, Express, Cloudflare, Hono), dual module formats (ESM and CommonJS), and TypeScript type definitions.
6. **Sandbox delivery status**: **`not-run` for all 21 providers**. Hooklatch executes no live network calls and does not solicit live vendor credentials in automated test suites. Local qualification is never presented as proof of live vendor interoperability.

---

## 21-Provider evidence matrix

All 21 providers appear below in exact built registry order (`src/providers/index.ts`). Every provider has an independent status across all verification dimensions.

| Provider | Algorithm | Fixtures (Ref / Local) | SDK comparison | Case counts | Runtime qualification | Sandbox delivery |
|---|---|---|---|---|---|---|
| `stripe` | HMAC-SHA256 | 19 (0 ref, 19 local) | not-compared | — | qualified-offline | not-run |
| `github` | HMAC-SHA256 | 9 (1 ref, 8 local) | not-compared | — | qualified-offline | not-run |
| `shopify` | HMAC-SHA256 | 7 (0 ref, 7 local) | not-compared | — | qualified-offline | not-run |
| `standard-webhooks` | HMAC-SHA256 | 17 (2 ref, 15 local) | compared (`standardwebhooks` v1.1.1) | 14 agree, 2 diverge | qualified-offline | not-run |
| `clerk` | HMAC-SHA256 | 16 (1 ref, 15 local) | not-compared | — | qualified-offline | not-run |
| `svix` | HMAC-SHA256 | 24 (2 ref, 22 local) | not-compared | — | qualified-offline | not-run |
| `razorpay` | HMAC-SHA256 | 20 (0 ref, 20 local) | not-compared | — | qualified-offline | not-run |
| `paddle` | HMAC-SHA256 | 33 (2 ref, 31 local) | compared (`@paddle/paddle-node-sdk` v3.10.0) | 11 agree, 3 diverge | qualified-offline | not-run |
| `lemon-squeezy` | HMAC-SHA256 | 15 (0 ref, 15 local) | not-compared | — | qualified-offline | not-run |
| `dodo-payments` | HMAC-SHA256 | 31 (0 ref, 31 local) | not-compared | — | qualified-offline | not-run |
| `gitlab` | HMAC-SHA256 | 34 (0 ref, 34 local) | not-compared | — | qualified-offline | not-run |
| `replicate` | HMAC-SHA256 | 31 (0 ref, 31 local) | not-compared | — | qualified-offline | not-run |
| `workos` | HMAC-SHA256 | 58 (0 ref, 58 local) | not-compared | — | qualified-offline | not-run |
| `sentry` | HMAC-SHA256 | 24 (0 ref, 24 local) | not-compared | — | qualified-offline | not-run |
| `doppler` | HMAC-SHA256 | 24 (0 ref, 24 local) | not-compared | — | qualified-offline | not-run |
| `sanity` | HMAC-SHA256 | 58 (0 ref, 58 local) | compared (`@sanity/webhook` v4.0.4) | 7 agree, 2 diverge | qualified-offline | not-run |
| `grafana` | HMAC-SHA256 | 50 (0 ref, 50 local) | not-compared | — | qualified-offline | not-run |
| `polar` | HMAC-SHA256 | 40 (0 ref, 40 local) | not-compared | — | qualified-offline | not-run |
| `linear` | HMAC-SHA256 | 31 (0 ref, 31 local) | compared (`@linear/sdk` v99.0.0) | 9 agree, 1 diverge | qualified-offline | not-run |
| `vercel` | HMAC-SHA1 | 33 (0 ref, 33 local) | docs-only probe | 4 docs probes | qualified-offline | not-run |
| `fal` | Ed25519 | 72 (0 ref, 72 local) | docs-only probe | 4 docs probes | qualified-offline | not-run |

---

## Historical pinned SDK differential comparisons

During Phase 10 qualification at commit `1747694b73b1c61254d99ad3217768650654d410`, Hooklatch was evaluated against four pinned official vendor SDKs across 49 test cases, alongside 8 documentation probes across 2 providers, yielding **57 total cases**:
- **41 protocol agreements**
- **8 documented receiver policy differences**
- **8 documentation-only probes**
- **0 unexpected mismatches**

The eight observed differences reflect receiver policies or API scope; they do not establish that one implementation is universally safer:

### 1. `standardwebhooks` (v1.1.1) — 16 cases (14 agreements, 2 divergences)
- **`std-divergence-auth-before-freshness`**: Hooklatch verifies cryptographic signatures before timestamp freshness (`invalid-signature`), so the reported reason for a bad MAC does not depend on freshness. The vendor SDK checks timestamp freshness first, throwing `WebhookVerificationError: Message timestamp too old`.
- **`std-divergence-weak-key`**: Hooklatch enforces `MIN_KEY_BYTES = 24` on symmetric secrets as a Hooklatch receiver policy (length alone does not establish entropy) (`invalid-secret`). The vendor SDK permits arbitrary secret lengths.

### 2. `@paddle/paddle-node-sdk` (v3.10.0) — 14 cases (11 agreements, 3 divergences)
- **`paddle-divergence-whitespace-segment`**: Hooklatch trims segment whitespace around semicolons as a Hooklatch receiver policy, accepting valid signatures even when headers contain formatted spacing (`ts=...; h1=...`). The Paddle Node SDK splits on `;` without trimming, producing key `" h1"` which fails parameter lookup and rejects the delivery.
- **`paddle-divergence-rotation-first-valid`**: Hooklatch treats repeated `h1` signatures as an accept-set for key rotation, validating successfully if any signature matches. The Paddle Node SDK loops and overwrites `h1`, evaluating only the final value.
- **`paddle-divergence-auth-before-freshness`**: Hooklatch verifies cryptographic authentication before timestamp freshness (`invalid-signature`). The vendor SDK checks timestamps first.

### 3. `@sanity/webhook` (v4.0.4) — 9 cases (7 agreements, 2 divergences)
- **`sanity-reject-default-tolerance-stale`**: Hooklatch enforces standard timestamp freshness (default 300 seconds; `timestamp-expired`). The Sanity SDK `assertValidSignature` checks only a minimum timestamp boundary and does not expire stale webhooks.
- **`sanity-divergence-empty-body`**: Hooklatch authenticates exact request bytes including empty string bodies (`""`). Sanity's `assertValidSignature` explicitly throws `WebhookSignatureFormatError` ("Can not create signature for empty payload").

### 4. `@linear/sdk` (v99.0.0) — 10 cases (9 agreements, 1 divergence)
- **`linear-divergence-stale-body-timestamp`**: Hooklatch core verifies exact visible request bytes without parsing JSON or extracting payload schema timestamps. The Linear SDK parses the JSON payload and asserts that the body field `webhookTimestamp` is within 60 seconds of `Date.now()`.

---

## Documentation-only probes

The historical corpus includes eight synthetic documentation-recipe probes (four cases each); these are not SDK comparisons:

1. **`vercel` (HMAC-SHA1)**: Verified against [Vercel Webhooks API documentation](https://vercel.com/docs/webhooks/webhooks-api). Requires single 40-character hexadecimal SHA-1 HMAC digest over the raw request body.
2. **`fal` (Ed25519)**: Verified against [fal.ai Webhooks documentation](https://fal.ai/docs/documentation/model-apis/inference/webhooks). The documented recipe uses Ed25519 over LF-separated identifiers, timestamp and body digest (`requestId\nuserId\ntimestamp\nsha256Hex(body)`). Hooklatch separately requires 1–16 caller-trusted raw 32-byte public keys and `expectedUserId` account binding as receiver configuration.

---

## Policy on uncompared providers

The remaining 15 supported providers (`stripe`, `github`, `shopify`, `clerk`, `svix`, `razorpay`, `lemon-squeezy`, `dodo-payments`, `gitlab`, `replicate`, `workos`, `sentry`, `doppler`, `grafana`, `polar`) are explicitly marked as **`not-compared`**.

Hooklatch strictly forbids extrapolating verification evidence across provider aliases or shared protocol standards:
- While `clerk` and `svix` use the Standard Webhooks cryptographic protocol, they maintain independent descriptor configurations and are **not** counted as SDK-compared rows.
- Only exact, pinned SDK comparisons executed against frozen package tarballs are recorded as `compared`.

---

## Provenance and historical receipts

Hooklatch anchors its qualification claims in cryptographic receipts and immutable artifacts:

- **Base commit**: `baa8a7427fbed42404f97d3b66c68c160ff1555f`
- **GitHub Actions CI verification**: [Run 40650684406](https://github.com/Its-amanjha/Hooklatch/actions/runs/40650684406) (completed `success` on 2026-10-29; all jobs passed: `verify (22)`, `verify (24)`, `node-floor (22.0.0)`)
- **Historical qualification tarball**: SHA-256 `6cf9be1540f498c992f80e3035e3bd3427cd2de3c90f5f911bb52c69e6ede9b8` (123,522 bytes)
- **Frozen historical receipts (SHA-256)**:
  - `coordinator-conformance-acceptance.json`: `453b51cabba98a82def7db0bc25474b6a605917843484c3a37066dc217ef8c16`
  - `coordinator-conformance-node22-results.json`: `24ce3d5cf50448146927a1437ddba40f86bd17b17dc538005e143c9364a138d3`
  - `coordinator-conformance-node24-results.json`: `9e2ac4bb4c3a348e27023ecfb94ea608ce632c0e56466d7f2fedb57df794ca04`
  - `compatibility-acceptance-baa8a74.json`: `7222e09211d0e0cf9f7f096082105d5bbc77c101fe1b1b28f614a3fe9670ac64`
  - `ci-success-2026-10-29.json`: `bb2b31d15bd214c8374ac9610420233fb2265a2a2151034a2f7e1f6d2d5aec8d`

---

## Safe sandbox-evidence acceptance checklist

Future contributions proposing live sandbox delivery evidence must satisfy this 5-point safety and reproducibility checklist before any row status may transition from `not-run`:

1. **Byte-exact capture**: The raw payload must be recorded exactly as transmitted over the wire prior to parsing or normalization, preserving line endings, whitespace, and binary bytes.
2. **Secret redaction and credential hygiene**: Production secrets, personal API tokens, authorization headers, and customer PII must be completely excluded or sanitized. Live sandbox signing secrets used for capture must be rotated immediately after capture.
3. **Account consent and authorization**: Captured webhooks must originate exclusively from dedicated test accounts owned and authorized by the contributor. No third-party or production accounts may be targeted.
4. **Immutable provenance**: Every captured delivery must document its capture timestamp, provider API version, delivery headers, and raw body SHA-256 digest alongside the source endpoint documentation.
5. **Deterministic offline execution**: Captured deliveries must be integrated as frozen offline JSON fixtures in `tests/fixtures/`. Verification test suites and fixture verification must run offline; dependency installation and other CI setup may require network access.
