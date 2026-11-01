# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest 1.x release | Yes |
| Older releases | No |

Security fixes are released only for the newest published version. To receive a
fix, upgrade to the latest release. No version has been published yet; this
policy applies from the first release.

## Reporting a Vulnerability

We take security seriously. If you discover a security issue in Hooklatch, please
report it responsibly.

**Do not** open a public issue for security vulnerabilities.

Report vulnerabilities privately through GitHub's private vulnerability
reporting: open the repository's **Security** tab and choose **Report a
vulnerability**, or go directly to
<https://github.com/Its-amanjha/Hooklatch/security/advisories/new>.
The report is visible only to you and the maintainers. A public issue or
discussion is not a private reporting channel.

Please include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce or a proof of concept.
- Any affected versions you have identified.

We will acknowledge receipt, investigate, and coordinate a fix and
disclosure timeline with you.

## Scope

Security issues include but are not limited to:

- Signature bypass or downgrade attacks
- Timing side-channels in signature comparison
- Secret leakage in error messages or logs
- Denial-of-service via unbounded body reads
- Dependency confusion or supply-chain risks

## Hall of Thanks

Researchers who report valid issues will be credited in release notes unless
they prefer to remain anonymous.
