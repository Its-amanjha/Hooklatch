# Provider guide

Reference for sixteen supported provider IDs plus two providers pending
integration and qualification. Paddle support covers Billing webhooks only.
Verification authenticates exact bytes before application parsing.

See [CLI scaffolding](cli.md) and [diagnostics](diagnostics.md).

## Qualified provider protocols

These sixteen providers are integrated and qualified in the current codebase.
The package has not yet been published to npm.

| ID | Header | Signed content | Secret form | Identity |
|---|---|---|---|---|
| stripe | `Stripe-Signature` (`t=...,v1=<hex>`) | `timestamp.body` | Literal string | timestamp authenticated |
| github | `X-Hub-Signature-256: sha256=<hex>` | body only | Literal string | unsigned delivery ID only |
| shopify | `X-Shopify-Hmac-Sha256: <base64>` | body only | Literal string | unsigned webhook/event IDs |
| standard-webhooks | `webhook-id`, `webhook-timestamp`, `webhook-signature` | `id.timestamp.body` | Base64-decode after `whsec_` strip | eventId + timestamp authenticated |
| clerk | `svix-*` branded triplet only | `id.timestamp.body` | Base64-decode after `whsec_` strip | eventId + timestamp authenticated |
| svix | `svix-*` or `webhook-*` triplet | `id.timestamp.body` | Base64-decode after `whsec_` strip | eventId + timestamp authenticated |
| razorpay | `X-Razorpay-Signature` | body only | Literal string | optional `x-razorpay-event-id` (unsigned, eventId) |
| paddle | `Paddle-Signature` (`ts=...;h1=...`) | `ts:body` | Literal string | timestamp authenticated; no IDs |
| lemon-squeezy | `X-Signature` | body only | Literal string | all identity fields null |
| dodo-payments | `webhook-id`, `webhook-timestamp`, `webhook-signature` | `id.timestamp.body` | Base64-decode after optional `whsec_` strip | eventId + timestamp authenticated |
| gitlab | `webhook-id`, `webhook-timestamp`, `webhook-signature` | `id.timestamp.body` | Base64-decode after optional `whsec_` strip | eventId + timestamp authenticated |
| replicate | `webhook-id`, `webhook-timestamp`, `webhook-signature` | `id.timestamp.body` | Base64-decode after optional `whsec_` strip | eventId + timestamp authenticated |
| workos | `workos-signature` (`t=...,v1=<hex>`) | `t.body` | Literal string | timestamp authenticated; no IDs |
| sentry | `sentry-hook-signature` | raw body | Literal string | all identity fields null |
| doppler | `x-doppler-signature` | raw body | Literal string | all identity fields null |
| sanity | `sanity-webhook-signature` | `UTF8(t + '.') + rawBody` | Literal string | timestamp authenticated |

### Authenticated vs unsigned identity

- **Authenticated identity** fields are covered by the signature and survive
  verification: `eventId`, `timestamp` where the protocol signs them.
- **Unsigned header metadata** (delivery IDs and event IDs on body-only
  protocols) is not covered by the signature. It does not stop replay or prove
  the header value was supplied by the provider. IDs inside signed payload bytes
  have integrity protection, but Hooklatch does not parse or extract them.

Body-only protocols (GitHub, Shopify, Razorpay, Lemon Squeezy, Sentry App,
Doppler signed mode) sign no timestamp, so freshness checks and ID headers
cannot stop replay on their own. A captured valid body and signature can be
replayed. Applications need their own replay/idempotency policy;
deduplicating an unsigned delivery header alone is not replay protection.

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

### Dodo Payments

For Dodo Payments, GitLab signing-token mode and Replicate, the default
freshness window is 300 seconds. Their authenticated `eventId` is the signed
`webhook-id` message identifier, not a business-event or resource ID extracted
from the payload. Retry consistency follows each provider's documented rules.

- **Protocol:** canonical Standard Webhooks recipe using `webhook-id`,
  `webhook-timestamp`, and `webhook-signature` headers only. No `svix-*`
  aliases, no legacy fallback, no JSON parsing, no event extraction.
- **Identity:** `eventId` = `webhook-id`, `deliveryId` = `null`,
  `authenticatedFields` = `['eventId', 'timestamp']`. Does not infer resource
  IDs or exactly-once semantics.
- **Secret:** canonical Standard Webhooks key handling; 24–64 decoded-byte
  limits apply.
- **Source:** https://docs.dodopayments.com/developer-resources/webhooks

### GitLab signing-token mode

- **Protocol:** canonical Standard Webhooks recipe using `webhook-id`,
  `webhook-timestamp`, and `webhook-signature` headers only. Signing tokens
  were introduced in GitLab 19.0 behind a flag and became generally available
  in 19.1. No fallback to the legacy `X-Gitlab-Token`; the legacy token is not
  authenticated-body support. Endpoints configured with only a secret token
  must migrate to a signing token before this provider can verify them.
- **Identity:** `eventId` = `webhook-id`, `deliveryId` = `null`,
  `authenticatedFields` = `['eventId', 'timestamp']`. These headers
  authenticate protocol bytes, not a unique vendor identity. Reusing secrets
  across endpoints can allow cross-endpoint replay; use endpoint-specific
  secrets and route configuration. Do not infer resource IDs or exactly-once
  semantics.
- **Secret:** canonical Standard Webhooks key handling; 24–64 decoded-byte
  limits apply.
- **Source:** https://docs.gitlab.com/user/project/integrations/webhooks/#signing-tokens

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
- **Precision qualification:** floating-point boundaries are tested using
  exactly representable fractional boundaries and integer-millisecond
  `Date.now` probes; Hooklatch does not claim mathematical sub-millisecond
  exactness.
- **Receiver policy vs SDK parity:** repeated-`v1`, strict grammar, and
  two-sided freshness are documented Hooklatch receiver policies, not claims
  of exact SDK millisecond-boundary parity. Hooklatch rejects leading-zero
  timestamps and accepts either hex case; the pinned Node SDK accepts leading
  zeros and compares lowercase signature text. SDK object serialization can
  also change whitespace or property order even for valid JSON, so retain the
  original request bytes rather than passing a parsed object.
- **Sources:** https://workos.com/docs/events/data-syncing/webhooks;
  pinned SDK https://raw.githubusercontent.com/workos/workos-node/ad8bff226e9b37435f0c62390318d4819f76b3d1/src/common/crypto/signature-provider.ts

### Sentry App

- **Provider id:** `sentry`.
- **Header:** `sentry-hook-signature` — exactly 64 hex characters, either hex
  case.
- **Missing or trim-blank header** → `missing-signature`. Every other malformed
  value → `malformed-signature`: prefixes, outer or inner whitespace,
  comma-combined duplicates, wrong length, nonhex characters, lists.
- **Signed content:** the exact raw body.
- **Identity:** all identity fields null; `authenticatedFields` empty.
- Ignore `request-id`, `sentry-hook-timestamp` and `sentry-hook-resource`; they
  cannot establish freshness or trusted identity.
- No claim is made for support of all Sentry webhook products.
- **Sources:** https://docs.sentry.io/integrations/integration-platform/webhooks/;
  https://github.com/getsentry/sentry/blob/72757dae9b6d527e564c81d4921dec0d62d7beca/src/sentry/sentry_apps/api/serializers/app_platform_event.py
- **Status:** implemented and locally qualified.

### Doppler signed mode

- **Provider id:** `doppler`.
- **Header:** `x-doppler-signature`.
- **Missing or trim-blank header** → `missing-signature`.
- Require one case-sensitive `sha256=` prefix followed by exactly 64 hex, either
  case. A scheme token accepted by `isSchemeToken`
  (`/^[A-Za-z0-9_-]+$/`) plus `=` plus exactly 64 hex but another scheme
  (e.g. `sha1=<64hex>`) → `unsupported-scheme`. All other nonconforming syntax
  → `malformed-signature`, including `sha1=<40hex>`, bare hex, commas, extra
  equals, leading/trailing whitespace and empty digest. Validate the whole value
  first; no unknown-field tolerance.
- **Signed content:** HMAC over the raw body.
- **Identity:** all identity fields null/empty; `authenticatedFields` empty.
- No Basic/Bearer fallback, unsigned acceptance, token auth, or replay-protection
  claim.
- **Source:** https://docs.doppler.com/docs/webhooks
- **Status:** implemented and locally qualified.

### Sanity

- **Provider id:** `sanity`.
- **Header:** `sanity-webhook-signature`.
- **HMAC input:** `UTF8(original millisecond timestamp text + '.')` concatenated
  with the exact untouched raw body. Key: literal UTF-8.
- **Accepted complete header is EXACTLY** `t=<ms>,v1=<digest>`: ordered fields,
  one each, no whitespace anywhere or outer trimming, extra fields, duplicate
  fields, semicolon separators, padding, or alternate versions.
- **Missing or trim-blank header** → `missing-signature`. Any other nonmatching
  structure → `malformed-signature` (including `t`-only, `v1`-only and
  `v2`-only).
- `ms` is a canonical nonnegative safe decimal integer (no leading zeros except
  `0`), at least `1609459200000` (2021-01-01 UTC). Earlier values →
  `malformed-signature`.
- `digest` is EXACTLY 43 characters from `A-Z a-z 0-9 _ -`, canonical unpadded
  Base64url decoding to 32 bytes. Re-encoding must match to reject nonzero
  unused pad bits. This encoding is distinct from standard Base64 used by
  Standard Webhooks-family protocols.
- **Identity:** `timestamp` = `Number(ms)/1000`, `deliveryId`/`eventId` =
  `null`, `authenticatedFields` = `['timestamp']`.
- **Freshness policy:** a two-sided, inclusive 300-second default
  window, with fractional epoch seconds from `Date.now()/1000`. A custom
  `now` returns epoch seconds; explicit tolerance `0` is zero-width and never
  bypasses freshness. The MAC is checked before freshness. This is Hooklatch
  receiver policy, not an established Sanity SDK recency default.
- Accept empty, NUL, invalid UTF-8 and non-JSON bodies as opaque bytes; this
  extends the string-oriented reference SDK. Do not claim exact SDK parity or
  live interoperability.
- Timestamp minimum/canonical spelling mirror bounded reference behavior; error
  codes are Hooklatch policy. Reject duplicates even when equal. No signature
  list or rotation within the header; configured multiple secrets still work in
  core.
- **Source:** https://github.com/sanity-io/webhook-toolkit/blob/e0c211ed6cd80465a70829e335c9e219f37839ba/src/signature.ts
- **Status:** implemented and locally qualified.

## Providers pending integration and qualification

The following two provider IDs are documented here only as planned protocol
mappings. They are **not registered or qualified for public verification**.
Do not treat anything in this section as advertised support.

| ID | Header | Signed content | Secret form | Identity | Status |
|---|---|---|---|---|---|
| grafana | `x-grafana-alerting-signature` (default name) | `UTF8(timestamp + ':') + rawBody` (timestamped mode); raw body (body mode) | Literal string | timestamp authenticated in timestamped mode; otherwise all fields null | Pending |
| polar | `webhook-id`, `webhook-timestamp`, `webhook-signature` | `id.timestamp.body` | Base64-decoded after optional `whsec_` strip (`current`); complete literal UTF-8 (`legacy`) | eventId + timestamp authenticated | Pending |

### Grafana

- **Provider id:** `grafana`.
- **Header names:** Grafana header names are lookup configuration, not
  authenticated bytes. The same key, body, and timestamp layout produce the
  same MAC regardless of the signature-header name; a MAC placed in the
  selected header may verify, and rescue from an unselected header is
  forbidden.
- **Signature header:** `x-grafana-alerting-signature` by default when none is
  configured; an explicit configured name may be used instead. Header names are
  nonempty RFC 9110 field-name tokens, with no whitespace trimming and
  case-insensitive lookup. Reserved names are rejected for either field:
  `host`, `content-length`, `transfer-encoding`, `connection`, `upgrade`,
  `trailer`, `te`, `proxy-authorization`, `proxy-authenticate`,
  `authorization`, `cookie`, `set-cookie`. This reserved list is Hooklatch
  configuration policy, not Grafana law.
- **Explicit mode required:** `body` or `timestamped`. In body mode, the
  signature covers the exact raw body; all identity fields are null and
  `authenticatedFields` is empty; timestamp headers are ignored. In timestamped
  mode, the signature covers `UTF8(timestamp + ':')` then the untouched raw
  body; `timestamp` is authenticated; `eventId` and `deliveryId` are null.
- **Signature value:** absent or trim-blank → `missing-signature`; otherwise
  exactly 64 hex characters, either hex case → 32 bytes; all whitespace,
  prefixes, commas, duplicates, lists, nonhex, or wrong length →
  `malformed-signature`. Signature structure is validated first.
- **Timestamped mode:** a present `timestampHeader` is required; missing or
  trim-blank → `missing-timestamp`; present text must be a canonical
  nonnegative safe integer in seconds (`0` valid; no sign, fraction, leading
  zero, whitespace, or comma) → noncanonical is `malformed-signature`.
- **Body mode forbids** any supplied `timestampHeader`, including an empty or
  explicitly undefined value.
- **Secret:** literal nonempty untrimmed UTF-8 string via the existing literal
  secret decoder.
- **Freshness:** timestamped mode uses an inclusive symmetric 300-second
  default window after signature authentication; explicit tolerance `0` is
  zero-width. Body mode has no signed timestamp and provides no freshness check.
  These are Hooklatch receiver policies, not a replay cache.
- **No fallback** to a default header when custom missing, other layout,
  Basic/Bearer, unsigned headers, or alien providers.
- **Source:** https://raw.githubusercontent.com/grafana/alerting/2acbeef29642fc3d89c7f3f0ad2f78e01c6d673e/http/hmac.go
- **Status:** pending integration and qualification.

### Polar

- **Provider id:** `polar`.
- **Protocol:** canonical Standard Webhooks recipe using `webhook-id`,
  `webhook-timestamp`, and `webhook-signature` headers only — no `svix-*`
  aliases, no legacy fallback, no JSON parsing, no event extraction.
- **Signed bytes:** `id.timestamp.body`; identity `deliveryId` = `null`,
  `eventId` = `webhook-id`, `timestamp` authenticated.
- **Secret mode (`current`, default):** existing strict canonical Base64
  decoding with the 24–64 decoded-byte limit.
- **Secret mode (`legacy`):** existing literal nonempty UTF-8 policy (full
  string as the HMAC key, including `whsec_` if present); no prefix
  requirement, inference, strip, or decode; no invented 24–256 bound.
- **One mode applies to all configured secrets; mixed-era accept sets are
  unsupported in this release.** No dual/auto mode; never silently try another
  key.
- **Timestamp:** canonical nonnegative safe decimal seconds (0 valid, no
  leading zeros except `0`); duplicate timestamp fails `malformed-signature`
  even when equal; MAC precedes freshness; default inclusive symmetric 300s;
  explicit tolerance `0` stays zero-width.
- **SDK differences (not parity):** the Polar SDK tries both keys, floors
  fractional timestamps, skips malformed tokens, and decodes byte bodies as
  text; Hooklatch does none of these. The 24–64 bound is Hooklatch's Standard
  Webhooks receiver policy, not a Polar guarantee.
- **Source:** https://raw.githubusercontent.com/polarsource/polar/89917ad4fe752b06ff84bd31c313d2a53a6085f1/sdk/typescript/src/webhooks.ts
- **Status:** pending integration and qualification.

## Cross-provider rules

- **Exact bytes only:** verification runs over the raw request bytes captured
  before any parsing or re-serialization. Empty, non-JSON, and invalid UTF-8
  bodies are preserved; never decode/re-encode the body to build signed
  content.
- **Key form:** literal nonempty untrimmed UTF-8 secrets are used by Stripe,
  GitHub, Shopify, Razorpay, Paddle, Lemon Squeezy, WorkOS, Sentry App,
  Doppler and Sanity. Standard Webhooks-family providers (standard-webhooks,
  Clerk, Svix, Dodo Payments, GitLab, Replicate) strip an optional `whsec_`
  prefix and Base64-decode the key, requiring 24–64 decoded bytes. A prefix alone never selects a
  protocol.
- **Key-length compatibility:** the decoded-key range is a Hooklatch limit
  based on Standard Webhooks guidance, not a guarantee about every vendor's
  issued secrets. An out-of-range key fails with `invalid-secret`.
- **Canonical aliases do not prove unique vendor identity:** Dodo Payments,
  GitLab signing-token mode and Replicate reuse the Standard Webhooks header
  grammar, as does the planned Polar current mode. Reusing secrets across
  endpoints can allow cross-endpoint replay; use endpoint-specific secrets and
  route configuration.
- **No payload parsing:** verification never parses or validates the payload
  schema.
- **Rotation:** accept-set, not business idempotency. Multiple active secrets
  are tried until one signature matches; this avoids delivery interruption
  during credential rotation but does not deduplicate business events.
- **Case-insensitive headers** through the normalizer. Repeated names are
  comma-combined; Web `Headers` can normalize surrounding whitespace. These
  transformations are distinct from preserving the signed body bytes. Record and
  tuple inputs preserve literal outer whitespace; Web `Headers` and `Request`
  remove it before verification. A strict raw-header rejection can therefore
  become valid for the normalized input without changing the signed body.

## What this guide does not cover

- No event extraction beyond the listed identity fields.
- No queue guarantees, retry, DLQ, or delivery semantics.
- No account setup, secret registration, or dashboard flows.
- Provider selection is explicit; automatic detection is not implemented.
- No Vercel/SHA-1, new algorithms, or dependency updates.
- No live-provider validation or exactly-once delivery claims.
- No Relay exists or is advertised: Relay is a future separately installed
  package; its name, backend and API are not frozen. Do not add queue switches
  or a Relay dependency to verification options. Never promise exactly-once
  business effects or provider retry guarantees.

Run `npm run verify` to check the local implementation, runtime, package and
generated-template gates. These checks do not imply live-provider validation.
