# Fixtures — schema and provenance policy

Owner: GLM (`tests/fixtures/**`). Consumers: `tests/verification/**`,
DeepSeek's provider tests, Beam's adapter tests. Contract version 1
(`notes/core-contract-proposal.md`) defines the meaning of every verdict.

## Files

- `stripe.json`, `github.json`, `shopify.json`, `standard-webhooks.json` — one
  case list per provider. Header keys are stored lowercase; the loader derives
  the record/tuple-list/`Headers` representations for parity checks.

## Schema

Every case:

- `id` — stable identifier, referenced from notes and failures.
- `provenance: { class: 'reference' | 'local', source, commit?: string, fetched?: string }`
  - `reference` = inputs AND expected value come from published provider
    material at the pinned URL/commit.
  - `local` = generated locally with `node:crypto` (test-only independent
    signing); never a published vector; inputs and generator are documented in
    `notes/glm-implementation.md`.
- `request.bodyBase64` — the exact request bytes (possibly empty), Base64 so
  byte-exactness survives diffs.
- `request.headers` — map of header name(s) to string or repeated values
  (string[]). Repeaters exercise HTTP comma combination.
- `options.secrets` — synthetic secret(s) exactly as the integrator would
  configure them (e.g. `whsec_…` for Standard Webhooks).
- `options.now` — fixed epoch seconds for the bounded clock;
  `toleranceSeconds` as configured.
- `expected.ok`, and for failures one exact `expected.reason` (contract v1 name).
  Editorial alternatives from the research phase were resolved during integration;
  tests must not accept multiple interchangeable failure codes.
- `expected.identity` — pinned `deliveryId`, `eventId`, `timestamp`,
  `authenticatedFields`. The sentinel `unsigned-or-null` means the identity
  field equals the corresponding request header when present, or null when absent.
  It is unsigned metadata, never an authenticated or fabricated identity.

## Rules

- Synthetic data only; the secrets in this directory are literal fixture
  strings, not credentials.
- No network, no timers: clocks come from `options.now` alone.
- Never edit a fixture to make a failing implementation pass; failing fixtures
  must be reported as integration findings back to the coordinator.
