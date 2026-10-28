# Security policy

## Reporting a vulnerability

Do not disclose suspected vulnerabilities in a public issue, discussion, pull request, diagnostic bundle, or chat transcript.

Use GitHub private vulnerability reporting from the repository's **Security** tab. Include:

- the affected version or commit;
- the operating system and agent involved;
- a minimal reproduction with synthetic data;
- the expected and observed protection behavior;
- the potential effect on confidentiality, integrity, policy enforcement, or audit records.

If private reporting is not enabled, open a public issue containing no vulnerability details and ask the maintainers for a private reporting channel.

## Sensitive material

Never submit real API keys, tokens, private keys, customer commands, raw agent transcripts, local databases, or unredacted diagnostic archives. `privometry doctor --bundle` performs redaction, but reporters must still inspect the archive before sharing it.

## Scope priorities

High-priority reports include policy bypasses, unsafe fail-open behavior, signature-verification flaws, path or permission weaknesses, secret leakage, cross-user access, hook-removal evasion, update compromise, and redaction failures.

## Supported versions

Until the first stable release, security fixes are made on the `main` branch. Once versioned releases are published, this section will list the supported release lines.
