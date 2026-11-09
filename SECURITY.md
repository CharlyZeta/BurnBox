# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.0.x   | :white_check_mark: |

## Reporting a Vulnerability

Security is a foundational pillar of BurnBox. If you find a security vulnerability, we appreciate your help in disclosing it responsibly.

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please send an encrypted or direct email report to:
`security@burnbox.io` or `gerardo@burnbox.local`

Include in your report:
- A detailed description of the vulnerability.
- Steps to reproduce or proof-of-concept (PoC).
- Potential impact and affected components.

We will acknowledge receipt within 48 hours and work with you on verification and remediation before public disclosure.

## Security Architecture Principles

BurnBox strictly follows the 12 principles defined in [`CONSTITUTION.md`](CONSTITUTION.md):
1. **Module Isolation:** All cryptographic code lives exclusively in `com.burnbox.crypto`. No `javax.crypto` references exist outside this boundary.
2. **Explicit Persistence:** Pure SQL with Spring Data JDBC and `JdbcClient` without JPA/Hibernate dirty tracking, preventing accidental updates or lazy-loading leaks.
3. **Deterministic Time:** Strict `Clock` bean injection. Direct calls to `Instant.now()` or `System.currentTimeMillis()` are forbidden and blocked by automated ArchUnit tests.
4. **Zero-PII Audit Ledger:** Security events are cryptographically hashed and chained with SHA-256 and append-only database triggers. Details never store plain secrets, tokens, or PII.
5. **Anti-Enumeration Responses:** Non-existent, expired, or access-restricted secrets return strictly indistinguishable HTTP 200 responses to prevent secret enumeration or email existence probing.
