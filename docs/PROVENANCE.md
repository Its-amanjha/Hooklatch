# Source and reference review

Reviewed on 2026-10-19. This is a bounded comparison of specific snapshots,
not a certification that every line is original or a determination of rights.

## Scope

- Hooklatch: `544b09f27d4fa520d24da74ad08c214f3a5b1abe`.
- Reference: [Hookflo/Tern at
  `3739224566f1080e7ebcdf57e1e145fcfde0e0c1`](https://github.com/Hookflo/tern/tree/3739224566f1080e7ebcdf57e1e145fcfde0e0c1).
- Compared 67 tracked Hooklatch TypeScript/JavaScript files, including source,
  tests, examples, scripts and executable configuration, with 37 corresponding
  language files in the reference repository. Also compared Hooklatch's README,
  architecture, contributing and security docs against the reference Markdown.
- Excluded dependency trees, lockfiles, generated output and standard license
  wording from code-similarity findings. No reference code was executed, built,
  installed as a dependency or copied into Hooklatch's implementation.

## Findings

The user describes the idea's origin as a general discussion on X about building
a tool in this category, followed by their own refinements and an LLM-generated
implementation brief. They did not identify Tern as the product they saw or as
their inspiration.

The generated brief nevertheless contained Tern's product identity, package
namespace, service-class API names and a similar proposed directory structure.
That is evidence about the prompt's contents, not evidence that the user copied
or drew inspiration from Tern. Why the prompt generator included those details
has not been established. The inherited identity was replaced before
publication. Tern was selected for this comparison because of that naming and
API overlap; the comparison does not make it the origin of the user's idea.

The implementation currently has materially different organization:

| Area | Hooklatch snapshot | Tern snapshot |
| --- | --- | --- |
| Public verification | Functions: `verify`, `verifyRequest`, `createVerifier` | `WebhookVerificationService` static methods |
| Core structure | Pure provider descriptors plus a shared verification engine | Config-driven algorithm verifiers and a base verifier class |
| Cryptography | Web Crypto HMAC verification | Node crypto imports in core/verifier modules |
| Verified input/output | Explicit raw byte input; byte snapshot on success; caller parses | Web Request/service API and payload-bearing result |
| Delivery | Deferred | Queue and notification modules present |

These are observed differences, not claims that the choices are inventions or
that one product is generally superior.

### Automated overlap checks

- No complete language file matched after normalizing CRLF to LF.
- Parsed TypeScript syntax-token comparison skipped whitespace/comments, retained identifiers/literals,
  and normalized the renamed error/package strings back to their old names to
  reduce the effect of rebranding. An eight-token seed located candidate runs;
  runs were extended until tokens differed. No matching run exceeded 16 tokens.
- The longest run was 16 tokens in header-entry iteration syntax. Other leading
  runs included 15-token byte-buffer setup/loop syntax. Manual
  review of these and other leading matches found routine typed-array loops,
  framework response signatures, timestamp expressions and response construction.
  Short matches do not establish either copying or independent authorship.
- The matcher recovered an injected, separately scanned copy of a 549-token
  local module embedded between extra tokens as a positive control.
- Word comparison of the four Hooklatch docs against the reference Markdown
  found a longest exact run of six words, a generic contributor greeting. Code
  fences were included; this was not a semantic paraphrase detector.

Manual review also covered both projects' entry points, public types,
verification/crypto architecture and framework adapters. No distinctive copied
implementation block or copied documentation passage was identified in this
review. This is limited evidence, not proof that copying never occurred.

## Reference vectors and attribution

Protocol constants, published test inputs and expected signatures are external
reference material. They must not be presented as newly invented by Hooklatch.

- GitHub: the published verification vector from [validating webhook
  deliveries](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries).
- Standard Webhooks: the reference signing vector from the [official JavaScript
  test suite at the pinned commit](https://github.com/standard-webhooks/standard-webhooks/blob/7537d2a2d3d52d8f2e0ecd12527af4a9307fd81b/libraries/javascript/src/webhook.test.ts).
- Stripe and Shopify: fixtures are labeled locally generated synthetic cases,
  not published provider reference vectors. Their declared signing inputs and
  methods remain in fixture provenance.

These vectors appear in provider tests, shared fixtures and offline Worker
fixtures. Original source links in fixture metadata and comments must remain.
Hooklatch's package license is not a substitute for attribution to the original
vector sources.

### Unresolved reference metadata

At the pinned Standard Webhooks commit, the repository's [root
license](https://github.com/standard-webhooks/standard-webhooks/blob/7537d2a2d3d52d8f2e0ecd12527af4a9307fd81b/LICENSE)
is Apache-2.0, while the [JavaScript package
manifest](https://github.com/standard-webhooks/standard-webhooks/blob/7537d2a2d3d52d8f2e0ecd12527af4a9307fd81b/libraries/javascript/package.json)
declares MIT. No JavaScript-local LICENSE or root NOTICE was found at the
checked paths. Clarify the applicable source terms before describing all
third-party fixture material as Hooklatch-authored MIT content. This review
does not decide whether particular signature test values require permission
or which declaration governs. No third-party implementation was added here.

## Limits and publication statements

This review covers one current reference snapshot, not its full history or all
other projects. It cannot establish where an LLM learned a pattern, rule out
paraphrased copying, reconstruct pre-Git edits or establish trademark clearance.
The reconstructed dates in the initial Git history are not authorship evidence;
see [history provenance](GIT_HISTORY.md).

Accurate public positioning is: Hooklatch is a TypeScript webhook verification
project with the implementation choices documented above. Its user's stated
idea origin and the generated prompt's inherited identifiers are separate facts.
It is not affiliated with Hookflo or Tern. Preserve actual source attribution
and investigate any specific future match before reusing it or claiming
exclusive authorship.
