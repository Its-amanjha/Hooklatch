# Provider guide

Reference for nine supported provider IDs plus four providers pending
integration and qualification. Paddle support covers Billing webhooks only.
Verification authenticates exact bytes before application parsing.

See [CLI scaffolding](cli.md) and [diagnostics](diagnostics.md).

## Original provider protocols

These six providers retain their existing signing and freshness policies.

| ID | Header | Signed content | Secret form | Identity |
|---|---|---|---|---|
| stripe | `Stripe-Signature` (`t=...,v1=<hex>`) | `timestamp.body` | Literal string | timestamp authenticated |
| github | `X-Hub-Signature-256: sha256=<hex>` | body only | Literal string | unsigned delivery ID only |
| shopify | `X-Shopify-Hmac-Sha256: <base64>` | body only | Literal string | unsigned webhook/event IDs |
| standard-webhooks | `webhook-id`, `webhook-timestamp`, `webhook-signature` | `id.timestamp.body` | Base64-decode after `whsec_` strip | eventId + timestamp authenticated |
| clerk | `svix-*` branded triplet only | `id.timestamp.body` | Base64-decode after `whsec_` strip | eventId + timestamp authenticated |
| svix | `svix-*` or `webhook-*` triplet | `id.timestamp.body` | Base64-decode after `whsec_` strip | eventId + timestamp authenticated |

### Authenticated vs unsigned identity

- **Authenticated identity** fields are covered by the signature and survive
  verification: `eventId`, `timestamp` where the protocol signs them.
- **Unsigned header metadata** (delivery IDs and event IDs on body-only
  protocols) is not covered by the signature. It does not stop replay or prove
  the header value was supplied by the provider. IDs inside signed payload bytes
  have integrity protection, but Hooklatch does not parse or extract them.

Body-only protocols (GitHub, Shopify) sign no timestamp, so freshness checks
and ID headers cannot stop replay on their own. A captured valid body and
signature can be replayed. Applications need their own replay/idempotency policy;
deduplicating an unsigned delivery header alone is not replay protection.

## Additional providers (integrated, qualified)

These providers use the same public verification APIs, diagnostics, scaffolding
CLI, and framework adapters.

| ID | Header | Signed content | Secret form | Identity |
|---|---|---|---|---|
| razorpay | `X-Razorpay-Signature` | body only | Literal string | optional `x-razorpay-event-id` (unsigned, eventId) |
| paddle | `Paddle-Signature` (`ts=...;h1=...`) | `ts:body` | Literal string | timestamp authenticated; no IDs |
| lemon-squeezy | `X-Signature` | body only | Literal string | all identity fields null |

### Razorpay

- **Header:** `X-Razorpay-Signature` — single 64-hex HMAC-SHA256 over the raw
  body.
- **Missing / whitespace-only header** → `missing-signature`. Other invalid
  tokens, comma-combined duplicates, prefixes, or lists → `malformed-signature`.
- **Identity:** optional `x-razorpay-event-id` maps to `eventId`, never
  authenticated; absent or whitespace-only → `null`, otherwise preserved
  without further trim. `deliveryId` and `timestamp` are `null`;
  `authenticatedFields` is empty.
- **Optional metadata does not affect signature acceptance.**
- **Source:** https://razorpay.com/docs/webhooks/validate-test/

### Paddle Billing only

- **Header:** `Paddle-Signature` — semicolon-delimited `key=value` fields.
- Exactly one canonical nonnegative safe decimal `ts`; at least one `h1`, each
  exactly 64 hex. Repeated `h1` values are a Hooklatch accept-set policy, not
  a claim of distinct-key SDK parity. Every `h1` must be valid; a malformed one
  poisons the whole header.
- Unknown nonempty scheme-token fields (such as `h2`) may be ignored after
  validation. Their values must be nonempty printable ASCII without whitespace,
  commas, semicolons, or extra equals signs. Invalid key / empty value / empty
  segment / commas → `malformed-signature`. Duplicate `ts` is always malformed.
- Missing/blank header → `missing-signature`; no `h1` but other valid
  signature versions → `unsupported-scheme`; `ts`-only → `missing-signature`;
  valid `h1` but absent `ts` → `missing-timestamp`; malformed present `ts` →
  `malformed-signature`. Structure and all tokens are validated before
  required fields are checked.
- **Signed content:** exact `ts` UTF-8 + `:` + raw body bytes.
- `timestamp` is authenticated; `deliveryId`/`eventId` are `null`. Payload IDs
  are not parsed.
- **Default tolerance: 5 seconds, symmetric inclusive Hooklatch policy**
  (not exact SDK millisecond-boundary parity). Explicit override allowed;
  zero remains zero-width. This is stricter than pinned SDK future handling.
  Descriptors never enforce clocks themselves.
- **Source:** https://developer.paddle.com/webhooks/about/signature-verification/

### Lemon Squeezy

- **Header:** `X-Signature` — single 64-hex HMAC-SHA256 over the raw body.
- Same missing/malformed policy as Razorpay.
- All identity fields null; `authenticatedFields` empty.
- Provider UI secret-creation limits are not assumed to be a cryptographic
  verification restriction; use a nonempty literal secret, untrimmed.
- **Source:** https://docs.lemonsqueezy.com/help/webhooks/signing-requests

## Providers pending integration and qualification

The following four provider IDs are documented here only as planned protocol
mappings. They are **not publicly registered or qualified**.
Do not treat anything in this section as advertised support.

| ID | Header | Signed content | Secret form | Identity | Status |
|---|---|---|---|---|---|
| dodo-payments | `webhook-id`, `webhook-timestamp`, `webhook-signature` | `id.timestamp.body` | Base64-decode after optional `whsec_` strip | eventId + timestamp authenticated | Pending |
| gitlab | `webhook-id`, `webhook-timestamp`, `webhook-signature` | `id.timestamp.body` | Base64-decode after optional `whsec_` strip | eventId + timestamp authenticated | Pending |
| replicate | `webhook-id`, `webhook-timestamp`, `webhook-signature` | `id.timestamp.body` | Base64-decode after optional `whsec_` strip | eventId + timestamp authenticated | Pending |
| workos | `workos-signature` (`t=...,v1=<hex>`) | `t.body` | Literal string | timestamp authenticated; no IDs | Pending |

### Dodo Payments

- **Protocol:** canonical Standard Webhooks recipe using `webhook-id`,
  `webhook-timestamp`, and `webhook-signature` headers only. No `svix-*`
  aliases, no legacy fallback, no JSON parsing, no event extraction.
- **Identity:** `eventId` = `webhook-id`, `deliveryId` = `null`,
  `authenticatedFields` = `['eventId', 'timestamp']`. Does not infer resource
  IDs or exactly-once semantics.
- **Secret:** canonical Standard Webhooks key handling; 24–64 decoded-byte
  limits apply.
- **Source:** https://docs.dodopayments.com/developer-resources/webhooks
- **Status:** pending integration and qualification.

### GitLab signing-token mode

- **Protocol:** canonical Standard Webhooks recipe using `webhook-id`,
  `webhook-timestamp`, and `webhook-signature` headers only. Signing tokens
  were introduced in GitLab 19.0 behind a flag and became generally available
  in 19.1. No fallback to the legacy `X-Gitlab-Token`; the legacy token is not
  authenticated-body support.
- **Identity:** `eventId` = `webhook-id`, `deliveryId` = `null`,
  `authenticatedFields` = `['eventId', 'timestamp']`. These headers
  authenticate protocol bytes, not a unique vendor identity. Reusing secrets
  across endpoints can allow cross-endpoint replay; use endpoint-specific
  secrets and route configuration. Do not infer resource IDs or exactly-once
  semantics.
- **Secret:** canonical Standard Webhooks key handling; 24–64 decoded-byte
  limits apply.
- **Source:** https://docs.gitlab.com/user/project/integrations/webhooks/#signing-tokens
- **Status:** pending integration and qualification.

### Replicate

- **Protocol:** canonical Standard Webhooks recipe using `webhook-id`,
  `webhook-timestamp`, and `webhook-signature` headers only. No `svix-*`
  aliases, no legacy fallback, no JSON parsing, no event extraction.
- **Identity:** `eventId` = `webhook-id`, `deliveryId` = `null`,
  `authenticatedFields` = `['eventId', 'timestamp']`. Does not infer resource
  IDs or exactly-once semantics.
- **Secret:** canonical Standard Webhooks key handling; 24–64 decoded-byte
  limits apply.
- **Source:** https://replicate.com/docs/topics/webhooks/verify-webhook
- **Status:** pending integration and qualification.

### WorkOS

- **Header:** `workos-signature` — comma-separated `key=value` fields with outer
  segment whitespace trimmed. Field names are case-sensitive; whitespace around
  `=` is rejected (segments are trimmed only, not interior whitespace).
- **Secret:** literal nonempty untrimmed UTF-8 string. HMAC-SHA256 over
  `UTF8(original t text + ".")` concatenated with the exact raw body. Never
  decode/re-encode the body or parse JSON. Invalid UTF-8 behavior is a
  Hooklatch byte-preservation policy, not parity with SDKs that decode
  strings.
- **Signature:** `v1` value is exactly 32 bytes hex, either case.
- **Timestamp:** exactly one canonical nonnegative safe-decimal integer `t` in
  milliseconds (zero allowed, no leading zeros except `0`). Duplicate `t`
  fails `malformed-signature`, even when equal. Field order is independent.
- **Grammar:** repeated valid `v1` tokens form an accept-set; any malformed
  recognized `v1` poisons the header. Unknown names pass `isSchemeToken`; their
  values must be nonempty opaque printable ASCII excluding whitespace, commas,
  and equals signs. Empty segments / missing `=` / empty value / extra `=`
  fail `malformed-signature`. Whole structure is validated before required
  fields are checked.
- **Missing/blank whole header** → `missing-signature`. No `v1` after
  structure validation → `unsupported-scheme` if unknown fields are present,
  otherwise `missing-signature`. Valid `v1` but absent `t` →
  `missing-timestamp`. Bad present `t` → `malformed-signature`.
- **Identity:** `timestamp` = `Number(t)/1000`, `deliveryId`/`eventId` =
  `null`, `authenticatedFields` = `['timestamp']`. Payload IDs are not parsed.
- **Freshness:** no freshness logic in the descriptor; core verifies HMAC
  before freshness. **Default tolerance: 180 seconds.** Other timestamped
  providers retain their existing defaults (Paddle 5s, others 300s). The
  WorkOS default clock returns `Date.now()/1000`, retaining milliseconds;
  existing defaults remain floored seconds. Custom `now` is always seconds
  and may be fractional. Explicit tolerance `0` is zero-width, never bypass.
  Symmetric inclusive boundaries.
- **Planned precision qualification:** floating-point boundaries will be tested using exactly
  representable fractional boundaries and integer-millisecond `Date.now`
  probes; Hooklatch does not claim mathematical sub-millisecond exactness.
- **Receiver policy vs SDK parity:** repeated-`v1`, strict grammar, and
  two-sided freshness are documented Hooklatch receiver policies, not claims
  of exact SDK millisecond-boundary parity. No raw-body decoding beyond the
  byte-preservation policy above.
- **Sources:** https://workos.com/docs/events/data-syncing/webhooks;
  pinned SDK https://raw.githubusercontent.com/workos/workos-node/ad8bff226e9b37435f0c62390318d4819f76b3d1/src/common/crypto/signature-provider.ts
- **Status:** pending integration and qualification.

## Cross-provider rules

- **Exact bytes only:** verification runs over the raw request bytes captured
  before any parsing or re-serialization. Empty, non-JSON, and invalid UTF-8
  bodies are preserved; never decode/re-encode the body to build signed
  content.
- **Key form:** Stripe, GitHub, Shopify, Razorpay, Paddle, Lemon Squeezy and
  WorkOS use literal nonempty untrimmed UTF-8 secrets. Standard Webhooks,
  Clerk, Svix, Dodo Payments, GitLab and Replicate strip an optional `whsec_`
  prefix and Base64-decode the key, requiring 24–64 decoded bytes. A prefix
  alone never selects a protocol.
- **Canonical aliases do not prove unique vendor identity:** Dodo Payments,
  GitLab signing-token mode and Replicate reuse the Standard Webhooks header
  grammar. Reusing secrets across endpoints can allow cross-endpoint replay;
  use endpoint-specific secrets and route configuration.
- **No payload parsing:** verification never parses or validates the payload
  schema.
- **Rotation:** accept-set, not business idempotency. Multiple active secrets
  are tried until one signature matches; this avoids delivery interruption
  during credential rotation but does not deduplicate business events.
- **Case-insensitive headers** through the normalizer. Repeated names are
  comma-combined; Web `Headers` can normalize surrounding whitespace. These
  transformations are distinct from preserving the signed body bytes.

## What this guide does not cover

- No event extraction beyond the listed identity fields.
- No queue guarantees, retry, DLQ, or delivery semantics.
- No account setup, secret registration, or dashboard flows.
- No new public API, provider auto-detection, or `Provider` union changes.
- No Vercel/SHA-1, new algorithms, or dependency updates.
- No live-provider validation or exactly-once delivery claims.

All four pending providers are **pending integration and qualification**.
Run `npm run verify` to check the local implementation, runtime, package and
generated-template gates. These checks do not imply live-provider validation.
