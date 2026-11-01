# Hooklatch 1.0.0 release notes — DRAFT, UNRELEASED

> **DRAFT — UNRELEASED.** This is not a release announcement. No npm
> publication, Git tag, GitHub release or release date exists. Do not use this
> file as install instructions, a compatibility guarantee or a support promise.

## Status of this draft

- The package version in the development tree is `1.0.0`, but no tag or
  publication exists. A version string in `package.json` does not make a release.
- This draft describes proposed content for a first release. It is not evidence
  that a release happened and it does not authorize one.
- The last recorded public evidence in this repository describes earlier
  commits and is historical. It does not qualify a future release commit. See
  [verification evidence](verification-evidence.md) and
  [module compatibility](compatibility.md).
- A final release commit and artifact must be retested after metadata changes.
  Editing the version, changelog, README, these notes or package metadata
  produces a different artifact, so earlier local or CI results do not carry
  over.
- This draft has no release date. Do not add one until a maintainer authorizes
  the actual release.

## Proposed release content (not published)

### Verification core

- Asynchronous `verify` and `verifyRequest` APIs plus the synchronous
  `createVerifier` factory, with `HooklatchError` for setup/runtime failures.
- Verification checks signatures over the exact request bytes before the
  application parses or trusts the payload.
- Verification failures are returned as `{ ok: false, reason }`. Setup and
  runtime problems are thrown. Nine failure reasons and nine setup error codes
  form closed unions.
- `maxBodyBytes` defaults to 1 MiB and is enforced while reading. Signed
  timestamp freshness uses an inclusive tolerance window; `now` is injectable
  for tests.
- Parsing, schema validation, queues, retries, DLQ, alerting and business
  idempotency remain outside the core.

See [public entrypoints](api-stability.md#public-entrypoints),
[credential arms](api-stability.md#credential-arms) and the
[core API](../README.md#core-api).

### 21 providers with fixed algorithms

- The API exposes 21 provider IDs through explicit provider selection. There is
  no auto-detection and request data cannot select an algorithm.
- Nineteen providers use HMAC-SHA256, Vercel uses HMAC-SHA1, and fal uses
  Ed25519.
- Grafana requires explicit layout configuration. Polar uses one secret
  interpretation per verifier. Linear authenticates the body signature but does
  not parse or freshness-check the body timestamp. fal uses caller-trusted raw
  32-byte public keys and a required expected user ID, with no shared secret and
  no core JWKS fetch.
- Reference vectors and local synthetic fixtures cover all 21 IDs. Four pinned
  vendor SDK comparisons are historical offline evidence from an earlier
  commit; they are not a fresh comparison and not a 21-SDK conformance result.
- All 21 sandbox delivery statuses remain `not-run`. No live provider
  interoperability is claimed.

See the [supported protocols table](../README.md#supported-protocols), the
[21-provider evidence matrix](verification-evidence.md#21-provider-evidence-matrix)
and the
[historical SDK comparisons](verification-evidence.md#historical-pinned-sdk-differential-comparisons).

### Node.js ESM and CommonJS

- Node.js 22 or later is required. The 22.0.0 floor was measured, along with
  later 22.x and 24.x lines. Node.js 18 and 20 are not supported.
- ESM and CommonJS resolve through conditional exports to one shared
  implementation. The neutral Workers ESM graph and the ESM CLI are retained.
- Same-process `import` and `require` identity is bounded to one installed copy
  and one realm; it does not cross worker threads, isolates, duplicate package
  trees or versions.
- No universal bundler, browser, Deno or Bun support is claimed.

See [module compatibility](compatibility.md) and
[what the current package supports](compatibility.md#what-the-current-package-supports).

### Optional adapters, CLI and diagnostics

- Express, Hono, Next.js App Router and Cloudflare Workers adapters live on
  isolated subpaths. Express and Hono remain optional peers; the core and
  diagnostics entries do not load them.
- The CLI generates one TypeScript endpoint file from the shipped adapters. It
  does not verify webhooks, start servers, install packages or use the network.
  A dry run prints the target path and contents without writing files.
- Diagnostics are static guidance for a validated reason/provider and ignore
  request messages and payloads.

See [adapters](api-stability.md#adapters), the [CLI reference](cli.md) and
[diagnostics](diagnostics.md).

### Package and distribution shape

- The package declares `"type": "module"` and `"engines": { "node": ">=22" }`,
  exposes six public subpaths with Node `import` and `require` conditions, and
  keeps the CLI `bin`.
- Runtime dependencies remain at zero. Express and Hono stay optional peers.
- The package's `files` manifest lists `dist`, `README.md` and `LICENSE`; tests,
  source, local notes and dependency trees are excluded. No publication has
  occurred.

See the [production artifact review](release-checklist.md#4-review-the-production-artifact).

## Platform and scope limits

- Authentication only. No payload parsing, schema validation, business
  processing, duplicate suppression, queueing, retries, DLQ or alerting.
- No exactly-once business effects and no provider retry guarantee.
- No replay immunity beyond signed-timestamp freshness where a provider
  actually signs a timestamp. Body-only protocols need application policy after
  a successful result.
- No Node.js 18 or 20 support, no universal bundler support, and no browser,
  Deno or Bun claim.
- No live vendor or sandbox delivery evidence. The four historical SDK
  comparisons are not a 21-SDK conformance claim.
- Relay and separate delivery integrations are not implemented or authorized
  by this draft. A future `hooklatch-relay` package is a proposal, not an
  available or published component.
- The [candidate versioning policy](api-stability.md#candidate-versioning-policy)
  is not a published compatibility guarantee.

## Prepublication checklist (blocking, manual)

These steps are separate from the proposed content and from any code change.
Passing checks do not publish anything. The authoritative procedure is the
[first release checklist](release-checklist.md).

1. **Private vulnerability reporting and support policy.** Configure a real
   private advisory channel, update `SECURITY.md` with the actual contact and
   confirm the supported-version policy. No address, response time, SLA or
   private channel is invented by this draft. See
   [external prerequisites](release-checklist.md#5-external-prerequisites-manual-not-code).
2. **npm access, name and provenance.** Confirm account access to the
   `hooklatch` name, two-factor authentication, and the chosen
   provenance/trusted-publishing configuration. A registry 404 is not proof of
   ownership, reservation or availability.
3. **Final exact-SHA CI.** Run CI on the final release commit itself:
   `verify (22)`, `verify (24)` and the Node.js 22.0.0 floor job must succeed.
   A previous run is not inherited by a later commit. See
   [confirm exact-SHA CI](release-checklist.md#3-confirm-exact-sha-ci).
4. **Final artifact review.** Build, inspect `npm pack --dry-run --json`, check
   the file list and manifest, scan for secrets and private files, and record
   the tarball SHA-256. Repeat after any metadata change. See
   [review the production artifact](release-checklist.md#4-review-the-production-artifact).
5. **Final authorization.** Wait for an explicit maintainer instruction naming
   the version, tag and distribution channel. Then date the changelog entry,
   commit and verify the release metadata, push only when authorized, wait for
   exact-SHA CI on that final commit, review and hash that final artifact, create
   and push the annotated tag, publish the reviewed tarball, and create the
   GitHub release. Tag and npm publication are effectively irreversible. See
   [final authorization](release-checklist.md#6-final-authorization-and-irreversible-actions).
6. **Replace this draft.** The eventual release notes must describe the actual
   authorized release and its measured artifact. Do not publish this draft as
   the announcement and do not move `CHANGELOG.md` out of `Unreleased` on the
   strength of this file.

## Not included in this draft

- No release date, countdown or publication window.
- No download, installation, user or adoption counts.
- No security contact, response time, service level or support promise.
- No claim that the npm name is owned, reserved or available.
- No claim of live vendor interoperability or 21-SDK conformance.
- No compatibility guarantee beyond the candidate policy linked above.

## Review notes

- Treat code and the tracked public documentation as authoritative if this
  draft disagrees with them.
- This file may be reviewed before publication, but it must not be tagged,
  published or presented as final release notes.
- Any final release commit and artifact must be retested after metadata changes;
  previous evidence belongs to the commit that was actually measured.
