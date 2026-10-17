# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.0 development (unreleased) | Fixes tracked in this workspace |

This workspace does not establish that any version has been published. Maintainers
must define the supported release policy when publishing the first release.

## Reporting a Vulnerability

We take security seriously. If you discover a security issue in Tern, please
report it responsibly.

**Do not** open a public issue for security vulnerabilities.

No dedicated reporting address or private advisory channel is configured in this
workspace. Before publishing, maintainers should configure and document one.
Use the repository's private vulnerability-reporting flow when it is available.
Otherwise ask the maintainers for a private contact without posting exploit
details. A public discussion is not a private reporting channel.

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
