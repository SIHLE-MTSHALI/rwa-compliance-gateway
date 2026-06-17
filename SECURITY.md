# Security Policy

## Project Status

RWA Compliance Gateway is a pre-release Chainlink blueprint. It is not audited, not deployed for production use, and must not be used for real investor onboarding, real compliance decisions, or real RWA pool access.

No paid bug bounty is active yet. Do not infer reward eligibility unless a future version of this file links to an official bounty program.

## Reporting a Security Issue

Do not open a public issue with exploit details, private keys, API keys, raw PII, provider responses, legal documents, investor records, or proof-of-concept code.

Preferred reporting path before public launch:

1. Use GitHub private vulnerability reporting if it is enabled for this repository.
2. If private reporting is not enabled, open a minimal public issue saying only that a private security report is available and ask the maintainer to enable a private channel.
3. Do not disclose technical details publicly until the issue is acknowledged and a disclosure plan is agreed.

Maintainer response targets are best-effort during pre-release: acknowledge within 7 days and provide an initial severity assessment when enough detail is available.

## Supported Versions

| Version | Supported |
| --- | --- |
| Public releases | None yet |
| `main` and active PR branches | Best-effort review only |

## In Scope

- Compliance credential lifecycle: issue, renew, suspend, expire, revoke, and review-required states.
- Pool policy configuration, jurisdiction rules, accreditation rules, freshness checks, allocation caps, and reason codes.
- Provider adapter boundaries for KYC/KYB results and sensitive response handling.
- CRE provider result intake, renewal, revocation, scheduled checks, and no-log requirements.
- Credential registry storage, policy versioning, audit events, and access-check behavior.
- CCID binding and CCIP propagation of credential status to destination chains.
- Privacy risks involving investor identifiers, PII, provider responses, and audit trails.

## Out of Scope

- Social engineering, phishing, or physical attacks.
- Vulnerabilities requiring access to maintainer devices or accounts.
- Legal advice, regulatory classification, or claims that the architecture satisfies a specific jurisdiction's rules.
- Findings against third-party providers unless this repository's integration mishandles their data or output.
- Findings against hypothetical production deployments that do not exist.
- Reward requests when no bounty program has been announced.

## High-Risk Areas

| Risk | Expected mitigation direction |
| --- | --- |
| PII leakage | No raw names, addresses, tax IDs, beneficial owner data, documents, provider reports, emails, or phone numbers in chain state, events, logs, or commits |
| Wrong pool access | Reason-coded policy engine, explicit deny/review states, and no default allow |
| Provider compromise | Provider pause, short TTLs, evidence hashes, manual review fallback, and revocation path |
| Cross-chain spoofing | Validate CCIP router, source chain, source sender, schema version, nonce, and credential freshness |
| Stale destination state | Freshness timestamps and strict freshness checks in pool policy |
| Governance abuse | Scoped roles, timelocks, public policy-change events, and separation of issuer/compliance/admin powers |
| Regulatory overclaim | Docs describe architecture and assumptions only; legal claims require external counsel review |

## Secure Development Rules

- Never commit secrets, private keys, API keys, access tokens, raw PII, provider responses, investor records, or compliance documents.
- Use placeholders in `.env.example` files only.
- Before public launch, verify repository remotes, config, docs, and history do not contain embedded credentials.
- Treat provider responses, policy inputs, issuer configuration, investor-submitted data, and CCIP messages as attacker-controlled.
- Add tests for revoked access, expired access, manual review default behavior, allocation caps, stale nonce, wrong CCIP sender, and no raw PII in events/storage.
- Keep audit, bounty, provider partnership, legal approval, and production onboarding claims out of docs until they are true and linked.

## Audit Status

No external audit has been completed. Any future audit report should be linked here with date, scope, commit hash, and unresolved findings.

## Disclosure Policy

Coordinated disclosure is preferred. Public disclosure should wait until a fix is available or a mutually agreed disclosure date is reached, unless there is active exploitation or user safety risk that requires faster notice.