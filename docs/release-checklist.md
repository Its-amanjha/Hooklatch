# First release checklist

Status: preparation only, reviewed 2026-10-30. No npm publication, Git tag,
GitHub release or repository setting change has been made. Every step is manual
and maintainer-gated: passing checks do not publish anything.

## 1. Freeze the candidate

- Select one commit and record its full SHA, the date and the runtimes used.
  A release is qualified for that commit, not for a nearby branch head.
- Confirm `git status --porcelain` is empty. Build output and local notes are
  ignored, but a dirty tracked tree is not a release candidate.
- Documentation-only edits do not extend or re-run the code qualification of an
  earlier commit. State plainly which SHA was measured and when.
- Version, changelog and tag decisions belong to the final authorization step.
  This checklist does not bump the version. `CHANGELOG.md` stays `Unreleased`
  until the release commit.

## 2. Run the local gate

On a clean checkout of the frozen commit:

```bash
npm ci
npm run verify
```

`npm run verify` runs the gates serially and stops at the first failure: lint and
anti-slop, build (neutral ESM plus the Node CommonJS graph and ESM facades),
strict typechecks, coverage, Workers smoke and provider matrices, installed
package smoke, generated templates, configured qualification, crypto runtime,
mutations, public contracts, the documentation contract, API freeze, generated
runtime, Node distribution, and package/types/runtime/framework compatibility.

Notes:

- `npm run test:docs-contract` reads the built provider registry, so run
  `npm run build` first when invoking it on its own. Inside `npm run verify` it
  runs after the build.
- `npm run test:mutations` expects a clean checkout.
- Run the gate on one frozen tree with no concurrent writers. Do not treat an
  interrupted or overlapping run as a pass.

## 3. Confirm exact-SHA CI

The workflow in `.github/workflows/ci.yml` must be green for the exact candidate
commit, not a neighboring push:

- `verify (22)` and `verify (24)` run the full gate on each Node line.
- `node-floor` builds with Node 24, then executes the installed-consumer floor
  check on Node.js 22.0.0.

The last recorded success was run
[40650684406](https://github.com/Its-amanjha/Hooklatch/actions/runs/40650684406)
at `baa8a74` (checked 2026-10-29). Any later commit needs its own run; a previous
success is not inherited.

## 4. Review the production artifact

```bash
npm run build
npm pack --dry-run --json
```

Check the reported file list and manifest before creating anything publishable:

- The package declares `files` as `dist`, `README.md` and `LICENSE`. Tests,
  source, local notes, tasks, coverage output, tarballs and dependency trees must
  not appear.
- `package.json` keeps `"type": "module"`, `"engines": { "node": ">=22" }`, the
  six public entries with `node.import`/`node.require` conditions, the CLI `bin`,
  and zero runtime dependencies. Express and Hono stay optional peers.
- The build produces real `.cjs` modules and Node ESM facades, not a second
  implementation. Do not hand-edit generated output.
- Scan the tarball contents and documents for secrets, synthetic keys, private
  paths, author claims or local reports. A bounded scan is not proof of absence.
- Record the tarball SHA-256 with a local tool such as `sha256sum`, `shasum -a
  256` or `Get-FileHash -Algorithm SHA256`. The historical accepted artifact at
  `baa8a74` (2026-10-28) was
  `6cf9be1540f498c992f80e3035e3bd3427cd2de3c90f5f911bb52c69e6ede9b8`, 123,522
  bytes; any content change, including README edits, produces a different hash.
  Compare the release candidate against the artifact that was actually reviewed.

## 5. External prerequisites (manual, not code)

All of these are outside the repository gate and may remain blocked:

- **npm access.** Confirm account access to the `hooklatch` name, two-factor
  authentication and the chosen provenance/trusted-publishing configuration.
  A registry lookup for `hooklatch` returned HTTP 404 at the last recorded check;
  404 is not proof of ownership, reservation or availability. Recheck before
  relying on the name.
- **Private vulnerability reporting.** Private reporting was disabled at the last
  verified check. Enable a real private channel and update `SECURITY.md` with the
  actual contact before publishing. Do not invent an address, response time or
  service level.
- **Support policy.** `SECURITY.md` currently describes an unreleased policy.
  Confirm the supported-version and disclosure policy as a maintainer decision.
- **Repository metadata.** Review the draft in section 8. Any change to remote
  settings is a separate maintainer action and is not performed by this
  checklist.
- **Documentation site.** Deferred. No documentation domain is reserved or
  promised; link to this repository's README and docs for now.

## 6. Final authorization and irreversible actions

Wait for an explicit maintainer instruction that names the version, tag and
distribution channel. Then, in order:

1. Move the `Unreleased` changelog content into a dated release section using the
   actual release date.
2. Commit the release metadata change and create the annotated tag.
3. Push the commit and tag. Treat a pushed tag as public.
4. Publish to npm with the reviewed tarball and the configured provenance
   settings.
5. Create the GitHub release with the same notes.

`npm publish` and tag pushes are effectively irreversible. npm unpublish is
restricted and time-limited; it is not a rollback plan. If the artifact is wrong,
stop before publishing rather than relying on cleanup afterwards.

## 7. Post-publication checks

- Confirm the registry resolves the intended version and `latest` tag:
  `npm view hooklatch version dist-tags.latest`.
- Install into a fresh temporary project and check both loading forms from the
  installed package: an ESM `import` and a CommonJS `require` of the root entry.
- Run the installed CLI, for example
  `npx --no-install hooklatch init webhook --provider clerk --framework nextjs --dry-run`.
- Compare the installed package with the reviewed tarball hash. Allow for normal
  registry propagation delay before concluding a mirror is stale.
- If a defect is found, record it and let the maintainer choose deprecation,
  a patch release or another documented response. Do not promise an outcome that
  depends on the registry's policies.

## 8. Repository metadata draft (not applied)

- **Description:** Portable webhook signature verification with a zero-dependency
  core.
- **Homepage:** `https://github.com/Its-amanjha/Hooklatch#readme`, matching the
  current manifest. There is no separate documentation site.
- **Topics:** `webhooks`, `webhook-security`, `signature-verification`, `hmac`,
  `ed25519`, `typescript`, `express`, `hono`, `nextjs`, `cloudflare-workers`,
  `nodejs`.
- **Adoption wording:** report only measured facts. Repository stars are not user
  counts; zero stars does not prove zero users. Do not add download, adoption or
  compatibility claims that the evidence does not support.

## 9. Deferred work

- A hosted documentation site.
- Live provider and sandbox delivery trials. All recorded sandbox delivery
  statuses remain not run; local runtime and SDK comparisons are not vendor
  interoperability evidence.
- New providers, algorithms, runtime floors or delivery integrations.

## Reversible versus irreversible

| Action | Reversible? |
| --- | --- |
| Local build, tests, `npm pack --dry-run` | Yes, local only |
| Local commits on a scratch branch | Yes, until published |
| Pushed branch or pull request | Visible to others; do not force-rewrite shared history |
| Pushed Git tag | Public; treat as irreversible |
| `npm publish` | Public and effectively irreversible |
| GitHub release or repository setting change | Public; treat as irreversible |
