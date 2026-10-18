# Release checklist

Practical maintainer checklist for publishing Hooklatch to the public npm
registry. Written against the repository state at `7afdee6`.

**This document is a checklist, not an authorization.** Unchecked boxes do not
record completed release steps. No publication, tag, registry/account operation, or repository
setting change is performed by this file, and none was performed while writing
it. Steps that touch an account, registry, or repository setting are marked
**[account/registry]** and must be done deliberately by a maintainer.

## Scope

- Covers: preparing a release locally, repository metadata, choosing preview vs
  stable, publishing mechanics, provenance inputs, security reporting readiness,
  and the final pre-release gate.
- Does not cover: implementing features, or any decision about pending Phase 2
  work (CLI, diagnostics, new providers). Those are still in progress; their
  verification is a future step, listed in [Pending work](#pending-at-the-checklist-baseline).
- Every step is labelled by kind: **local**, **[account/registry]**, or
  **[repository setting]**.

## Current state (verified at `7afdee6`)

| Item | State |
| --- | --- |
| `package.json` `repository` | **absent** |
| `package.json` `author`, `bugs`, `homepage`, `keywords`, `funding` | absent (`bugs`/`homepage` optional — see 2.2; `author`/`funding` optional — see 2.3) |
| `package.json` `files` | `dist`, `README.md`, `LICENSE` |
| `package.json` `engines.node` | `>=22` |
| Runtime dependencies | none |
| `.github/workflows/ci.yml` | test-only: `permissions: contents: read`, Node 22 + 24 on `ubuntu-latest`, runs `npm ci && npm run verify`. No publish job, no release trigger |
| Git remote `origin` | `https://github.com/Its-amanjha/Hooklatch.git` |
| `docs/PROVENANCE.md` | present, includes the corrected nested-license record |
| README vector links | present (lines ~292–296) |

---

## 1. Local preparation

- [ ] **1.1 Build before packing.** `npm run build`.
      This is not optional bookkeeping. Verified: in a clean worktree with no
      prior build, `npm pack --dry-run` exits 0 and reports only **3 files**
      (`package.json`, `README.md`, `LICENSE`) and ~5.6 kB — because `dist/`
      does not exist and the `files` allowlist silently yields an empty code
      directory. The command still succeeds, so this failure is easy to miss.
- [ ] **1.2 Inspect the package contents.** `npm pack --dry-run`.
      Confirm `dist/index.js`, `dist/index.d.ts` and the adapter subpaths for
      `express`, `nextjs`, `cloudflare`, `hono` are present, and record the
      reported file count and size.
- [ ] **1.3 Confirm nothing sensitive is staged.** `npm pack --dry-run` lists
      every file that would ship. Check that no `.env*` (other than an
      intentionally sanitized `.env.example`/`.sample`/`.template`), no
      credential, and no internal-only file appears. The `files` allowlist is the
      primary control here; `docs/`, `notes/`, `tasks/`, `tests/` and `src/` are
      all excluded by it and should be absent from the listing.
- [ ] **1.4 Confirm attribution ships.** README is included in the tarball and
      already links the reference-vector sources and the pinned Standard Webhooks
      `libraries/LICENSE`. Confirm those links are still present in the README
      that will ship. `docs/PROVENANCE.md` is **not** shipped — the `files`
      allowlist excludes it — so the README links are the only attribution npm
      consumers will see.
- [ ] **1.5 Note sourcemaps are published.** `.js.map` files are inside
      `dist/`, so they ship. This is a deliberate-looking choice but is a
      public-surface decision; confirm it is intended rather than assumed.

## 2. Repository metadata

- [ ] **2.1 Add `repository` to `package.json`.** This is the one metadata
      omission that blocks a documented capability. npm documents that to publish
      with provenance you must "ensure your `package.json` is configured with a
      public `repository` that matches (case-sensitive) where you are publishing
      with provenance from"
      ([generating provenance statements](https://docs.npmjs.com/generating-provenance-statements)).
      Suggested value, matching the existing remote exactly:

      ```json
      "repository": {
        "type": "git",
        "url": "git+https://github.com/Its-amanjha/Hooklatch.git"
      }
      ```

      Match the case of the real remote. A mismatch weakens or fails provenance
      attestation.
- [ ] **2.2 Optionally add `bugs` and `homepage`.** Both help npm and GitHub
      surface an issue/security destination. Optional, not blocking.
- [ ] **2.3 Do not invent `author` or `funding` values.** These are optional and
      are not release blockers. Fill them in only with real information supplied
      by the maintainer. Do not guess a person, organisation, or payment link.

## 3. Choose the release shape

- [ ] **3.1 Decide preview vs stable.**
      `npm publish` sets the `latest` dist-tag unless `--tag` is used
      ([`npm publish`](https://docs.npmjs.com/cli/v11/commands/npm-publish)).
      A preview keeps `latest` pointed at the last stable release while exposing
      the new version under a named tag, which consumers install explicitly with
      `npm install hooklatch@<tag>`
      ([adding dist-tags](https://docs.npmjs.com/adding-dist-tags-to-packages)).
- [ ] **3.2 Pick a dist-tag name.** npm recommends avoiding tags that start with
      a number or the letter `v`, because dist-tags share a namespace with
      semantic versions.
- [ ] **3.3 Decide the version number and the Git tag.** The repository currently
      has version `1.0.0` in `package.json`. `SECURITY.md` still describes
      "1.0.0 development (unreleased)" and states that a supported-versions policy
      must be defined when publishing. Settle the version and that policy before
      announcing anything.
- [ ] **3.4 Do not assume the package name is held.** Whether `hooklatch` is
      registered on npm is not something this checklist asserts, and an
      unregistered name is not a reservation — names are not held by publishing
      documentation. If the name matters, the only protection is to publish it.

## 4. Publishing mechanics

- [ ] **4.1 Choose local or CI publishing.**
      *Local* is simplest for a first release and needs no workflow change. *CI*
      is what makes provenance and trusted publishing possible.
- [ ] **4.2 Do not add publication permissions to the verification workflow.**
      `.github/workflows/ci.yml` is a test-only workflow and is correct as-is
      with `permissions: contents: read`. Publishing permissions belong in a
      separate release workflow, never bolted onto the job that runs
      `npm run verify`.
- [ ] **4.3 If publishing from CI, add a separate release workflow** with
      `permissions: id-token: write`, `runs-on: ubuntu-latest`, and a trigger
      that is not every push. npm documents these prerequisites for provenance
      ([generating provenance statements](https://docs.npmjs.com/generating-provenance-statements)).
- [ ] **4.4 Choose public access explicitly in the release command.**
      Use `npm publish --access public` in the approved release plan. Hooklatch
      is unscoped, so it is always public; explicit access also matches npm's
      first-publish provenance example. The unscoped-package guide itself uses
      plain `npm publish`
      ([creating and publishing unscoped public packages](https://docs.npmjs.com/creating-and-publishing-unscoped-public-packages)).
- [ ] **4.5 Decide how CI authenticates.**
      Either an appropriately scoped granular access token used as
      `NODE_AUTH_TOKEN` with the required publishing/2FA permissions, or
      **trusted publishing (OIDC)**, which npm documents as removing the need for
      access tokens in CI and generating provenance automatically
      ([trusted publishing](https://docs.npmjs.com/trusted-publishers)).
      Trusted publishing requires npm CLI **11.5.1+** and Node **22.14.0+**;
      the older minimum for provenance alone does not satisfy this requirement.
- [ ] **4.6 Remember dist-tags under OIDC are a separate grant.** If using
      trusted publishing, enabling "Allow npm dist-tag" is a distinct permission,
      disabled by default, and requires npm CLI 11.21.0+ or 12.2.0+
      ([adding dist-tags](https://docs.npmjs.com/adding-dist-tags-to-packages)).

**[account/registry]** All of section 4's registry operations: publishing,
retagging, token creation, and trusted-publisher configuration.

## 5. Provenance

- [ ] **5.1 Understand what it does and does not prove.** npm states plainly that
      provenance "does not guarantee the package has no malicious code"; it
      provides a verifiable link to source and build instructions. Do not
      describe it as a security guarantee in release notes
      ([generating provenance statements](https://docs.npmjs.com/generating-provenance-statements)).
- [ ] **5.2 Inputs checklist.** Requires: a supported cloud CI/CD provider on a
      cloud-hosted runner; npm CLI 9.5.0+; a public `repository` in
      `package.json` matching the publishing location case-sensitively (see step
      2.1); and `id-token: write` for GitHub Actions. Provenance can also be
      enabled via `publishConfig.provenance`, `NPM_CONFIG_PROVENANCE`, or
      `provenance=true` in `.npmrc` — there is currently no `.npmrc` in this
      repository.
- [ ] **5.3 Verify after publishing.** Install the exact published Hooklatch
      version in a scratch project and run `npm audit signatures` there.
      Running it only in this repository audits its dependencies, not Hooklatch
      itself, which is not installed here as a dependency.

## 6. Security reporting

- [ ] **6.1 Check the current status first. It is UNKNOWN.**
      GitHub documents that owners/administrators of **public** repositories can
      enable private vulnerability reporting
      ([configuring private vulnerability reporting for a repository](https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/configuring-private-vulnerability-reporting-for-a-repository)).
      **This checklist does not know whether it is currently enabled on this
      repository.** That was not verified, because checking it requires
      authenticated repository access that was not authorized. Treat it as
      unknown — not as enabled, and not as disabled.
- [ ] **6.2 How to check.** Repository → **Settings → Security and quality →
      Advanced Security → Private vulnerability reporting**. The **Report a
      vulnerability** button appears on the repository's Advisories tab only when
      the feature is enabled
      ([privately reporting a security vulnerability](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/privately-reporting-a-security-vulnerability)).
      An account owner can confirm this directly and quickly.
- [ ] **6.3 Only then update `SECURITY.md`.** The current text is honest: it
      describes the private flow as available "when it is available" and says no
      dedicated reporting address is configured. Update it to describe a
      concrete, verified channel **only after step 6.2 confirms the channel
      exists**. Do not write wording that asserts an enabled channel before it
      has been checked, and do not promise a response time or support level that
      has not been agreed.
- [ ] **6.4 Keep the complementary parts.** GitHub documents that private
      vulnerability reporting is *separate from* `SECURITY.md`. Keeping a written
      policy is still worthwhile; the feature does not replace it.
- [ ] **6.5 Optional.** Add a reporting form via the documented YAML mechanism in
      `.github/`. Only if wanted.

**[repository setting]** Steps 6.1–6.2 and 6.5.

## 7. Final gate before release

- [ ] **7.1 Run the full local gate:** `npm run verify`. This covers lint,
      strict typechecks, build, examples, coverage, real-workerd tests and an
      isolated packed-package smoke.
- [ ] **7.2 Confirm the pushed revision's own CI result.** A green CI run belongs
      to a specific revision. Do not inherit a previous revision's result.
- [ ] **7.3 Re-run step 1.2** on the exact commit you are about to publish from,
      so the inventory reflects the released tree rather than a local edit.
- [ ] **7.4 Re-read the release notes** for claims the project cannot support.
      At this checklist's baseline only Stripe, GitHub, Shopify and Standard
      Webhooks are implemented; recheck the actual release revision. No
      live-provider verification, no QStash delivery, and no publication has ever
      occurred — none of that may be implied.

## 8. After publishing

- [ ] **8.1 Verify what landed:** `npm view hooklatch`, and confirm the dist-tags
      are what you intended (step 3.1/3.2).
- [ ] **8.2 Verify provenance** in the installed-package scratch project as
      described in step 5.3: `npm audit signatures`.
- [ ] **8.3 Confirm the Git tag** matches the published version.
- [ ] **8.4 Smoke the installed package** in a scratch directory outside the
      repository — not in this working tree — importing the core and, if relevant,
      one adapter.
- [ ] **8.5 CLI help smoke.** The Phase 2 CLI is **not yet implemented**. When it
      lands, `hooklatch --help` and `hooklatch init webhook --help` must be
      confirmed to work from an *installed* package, not only from the repo, since
      the bin wiring is the part most likely to differ. This is a future check and
      is not satisfied by today's tests.

---

## Reference material on published signatures

- The GitHub vector comes from vendor **documentation**; the Standard Webhooks
  vector comes from a **published reference test suite**. Keep both source links
  in the README.
- The corrected license record — including the nested MIT notice under
  `libraries/` that an earlier review omitted — is in
  [`docs/PROVENANCE.md`](PROVENANCE.md). Read it before changing any attribution
  or license wording.
- **Recomputing the same HMAC does not remove the identical bytes and does not
  establish different rights.** Do not regenerate a published reference vector
  and present that as a licensing remedy. The reference inputs and their
  attribution are retained deliberately; no legal determination is claimed
  anywhere in this repository.

## Pending at the checklist baseline

- Phase 2 CLI scaffolding and diagnostics — in progress, unimplemented.
- New provider presets (Clerk/Svix) — approved design, not yet implemented.
- Verifying the CLI/diagnostics/providers once implemented.
- Delivery/QStash — deferred by decision, not pending implementation.
- A third-party notices file beyond the README links.
- npm SBOM generation.

## Sources

All URLs below returned HTTP 200 when checked on 2026-10-19.

- [Creating and publishing unscoped public packages](https://docs.npmjs.com/creating-and-publishing-unscoped-public-packages)
- [Generating provenance statements](https://docs.npmjs.com/generating-provenance-statements)
- [Trusted publishing with OIDC](https://docs.npmjs.com/trusted-publishers)
- [Adding dist-tags to packages](https://docs.npmjs.com/adding-dist-tags-to-packages)
- [`npm dist-tag`](https://docs.npmjs.com/cli/v12/commands/npm-dist-tag)
- [`npm pack`](https://docs.npmjs.com/cli/v12/commands/npm-pack)
- [`npm publish`](https://docs.npmjs.com/cli/v11/commands/npm-publish)
- [Configuring private vulnerability reporting for a repository](https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/configuring-private-vulnerability-reporting-for-a-repository)
- [Privately reporting a security vulnerability](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/privately-reporting-a-security-vulnerability)
