/**
 * Shared fixtures for the offline Workers runtime smoke harness.
 *
 * Imported by `tests/workers/worker.ts` (bundled into the Worker) and by
 * `scripts/workers-smoke.mjs` (Node side, for building and asserting requests)
 * so both sides read one source of truth.
 *
 * Provenance: the GitHub and Standard Webhooks values below are published
 * reference vectors from official documentation/reference suites. They are
 * public test data, not credentials. Both were independently recomputed with
 * .NET `HMACSHA256` on 2026-10-18 before being embedded here. Official source
 * links accompany the vectors below.
 *
 * Everything else is synthetic: fixed clock, synthetic delivery ID, and
 * locally derived variants used to drive negative cases.
 */

/**
 * Pinned Workers compatibility date.
 *
 * The workerd binary shipped by the installed Miniflare (workerd
 * 1.20260730.1) refuses any date after 2026-08-06, so this is the newest date
 * this harness may pin. Revisit when the dev dependency is upgraded.
 */
export const COMPATIBILITY_DATE = '2026-08-06';

/** Origin used for all offline `dispatchFetch` calls. Never leaves the process. */
export const ORIGIN = 'https://tern-workers-smoke.invalid';

/* -------------------------------------------------------------------------- */
/* GitHub — published reference vector (official docs)                        */
/* -------------------------------------------------------------------------- */

export const GITHUB_SECRET = "It's a Secret to Everybody";
export const GITHUB_BODY = 'Hello, World!';
export const GITHUB_SIGNATURE_HEX =
  '757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17';
export const GITHUB_SIGNATURE_HEADER = `sha256=${GITHUB_SIGNATURE_HEX}`;
/** Synthetic delivery GUID. Unsigned metadata in the GitHub protocol. */
export const GITHUB_DELIVERY_ID = '00000000-0000-4000-8000-000000000001';

/* -------------------------------------------------------------------------- */
/* Standard Webhooks — published reference vector (official JS reference suite) */
/* -------------------------------------------------------------------------- */

export const STANDARD_WEBHOOKS_SECRET = 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw';
export const STANDARD_WEBHOOKS_ID = 'msg_p5jXN8AQM9LWM0D4loKWxJek';
export const STANDARD_WEBHOOKS_TIMESTAMP = 1614265330;
export const STANDARD_WEBHOOKS_BODY = '{"test": 2432232314}';
export const STANDARD_WEBHOOKS_SIGNATURE =
  'v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=';

/**
 * Locally derived (NOT published): a correctly signed Standard Webhooks
 * message whose timestamp sits outside the default 300s tolerance relative to
 * `FIXED_NOW`. The harness derives the signature with `node:crypto` so the
 * failure under test is freshness, not cryptography.
 */
export const STANDARD_WEBHOOKS_EXPIRED_OFFSET_SECONDS = 400;

/* -------------------------------------------------------------------------- */
/* Fixed clock and env bindings                                                 */
/* -------------------------------------------------------------------------- */

/** Fixed "now" in epoch seconds. Equal to the Standard Webhooks vector's ts. */
export const FIXED_NOW = STANDARD_WEBHOOKS_TIMESTAMP;

export const ENV_MARKER = 'tern-workers-smoke-marker-v1';

/**
 * Bindings handed to the Worker through Miniflare. The Worker resolves its
 * signing secrets and its clock from these, so a passing run also proves env
 * binding resolution works inside workerd.
 */
export const ENV_BINDINGS = Object.freeze({
  TERN_GITHUB_SECRET: GITHUB_SECRET,
  TERN_STANDARD_WEBHOOKS_SECRET: STANDARD_WEBHOOKS_SECRET,
  TERN_NOW: String(FIXED_NOW),
  TERN_MARKER: ENV_MARKER,
});

/* -------------------------------------------------------------------------- */
/* Routes                                                                      */
/* -------------------------------------------------------------------------- */

export const ROUTE_RUNTIME = '/probe/runtime';
export const ROUTE_REQUEST_WRAPPER = '/probe/request-wrapper';
export const ROUTE_REQUEST_WRAPPER_STANDARD_WEBHOOKS = '/probe/request-wrapper/standard-webhooks';
export const ROUTE_GITHUB = '/webhooks/github';
export const ROUTE_STANDARD_WEBHOOKS = '/webhooks/standard-webhooks';

/**
 * Body limit for the direct `verifyRequest` probe route only. Deliberately
 * small so the overflow path is exercised without a large fixture. The adapter
 * routes use the core default so adapter behaviour is tested as shipped.
 */
export const PROBE_MAX_BODY_BYTES = 32;

/* -------------------------------------------------------------------------- */
/* Negative-case bodies                                                        */
/* -------------------------------------------------------------------------- */

/** Same length as GITHUB_BODY with exactly one byte changed. */
export const GITHUB_TAMPERED_BODY = 'Hello, World?';

/** Same length as STANDARD_WEBHOOKS_BODY with exactly one byte changed. */
export const STANDARD_WEBHOOKS_TAMPERED_BODY = '{"test": 2432232315}';

/** Larger than PROBE_MAX_BODY_BYTES; triggers `body-too-large`. */
export const OVERSIZED_BODY = 'x'.repeat(PROBE_MAX_BODY_BYTES + 1);
