# Contributing to RWA Compliance Gateway

Thank you for helping improve RWA Compliance Gateway. This repository is intended to become public, so contributions should make the project more credible, privacy-preserving, and buildable without overstating what exists today.

## Current Stage

This project is in product design and early implementation planning. Treat `PRD.md` as the canonical scope document until code, deployment scripts, and audits exist.

Do not add claims about production investor onboarding, legal or regulatory approval, live RWA pools, completed audits, Chainlink endorsement, bug bounties, or provider partnerships unless there is verifiable evidence in the repository.

## Contribution Focus

High-value contributions should improve one of these areas:

- Compliance credential lifecycle: issue, renew, suspend, expire, revoke, and review-required states.
- Pool policy design for jurisdiction, accreditation, freshness, allocation caps, and manual review rules.
- Provider adapter boundaries for KYC/KYB results without storing raw PII on-chain.
- CRE workflow design for provider result intake, renewal, revocation, and scheduled checks.
- CCID binding and CCIP propagation of credential status to destination chains.
- Reason-coded pool access checks that distinguish allow, deny, and review.
- Public privacy, legal-limitation, issuer, investor, and auditor documentation.

## Product Quality Bar

Contributions should keep the product compliance-serious and privacy-first:

- Never store or emit raw investor PII, documents, tax IDs, beneficial ownership data, names, emails, phone numbers, or provider reports on-chain.
- Manual review must not default to allow.
- Legal claims require external legal review; docs should describe architecture and assumptions, not promise compliance.
- Destination-chain credential state must expose freshness and source information.
- Keep docs aligned with the MVP and non-goals in `PRD.md`.

## Engineering Standards

When implementation begins, code contributions should follow these expectations:

- Use Foundry for Solidity contracts unless the repository later standardizes otherwise.
- Pin compiler and dependency versions.
- Add NatSpec for public and external contract interfaces.
- Use role-based access control for admin, issuer, compliance officer, emergency pauser, and auditor roles.
- Validate CCIP router, source chain selector, source sender, schema version, nonce, and credential freshness.
- Version policy changes and emit enough information for audit without exposing PII.
- Keep CRE workflow outputs deterministic and prohibit sensitive provider responses in logs.
- Use `bigint` for on-chain values in TypeScript workflows and tests.

## Verification Expectations

Use the narrowest useful check first, then broaden.

| Change type | Expected verification |
| --- | --- |
| Docs only | Check links, headings, terminology, and alignment with `PRD.md` |
| Solidity contracts | `forge fmt --check`, unit tests, fuzz tests, and relevant invariant tests |
| Policy logic | Tests for allow, deny, review, allocation caps, jurisdiction rules, expiry, and revocation |
| CRE workflows | Simulation tests for provider pass, fail, manual review, timeout, malformed response, and revoked provider |
| CCIP flows | Local simulator tests for propagation, replay, wrong source, stale nonce, and destination pause |

If a check cannot run, explain the blocker in the PR instead of presenting the work as fully verified.

## Pull Request Checklist

Before opening a PR:

- The change maps to a requirement, risk, or open question in `PRD.md`.
- Public-facing docs do not include fake deployments, fake provider claims, fake legal approvals, fake audits, fake bounty details, or production investor onboarding claims.
- Privacy-sensitive changes state what data is processed, stored, emitted, logged, and intentionally excluded.
- Tests or verification notes cover the behavior changed.
- New environment variables are documented with placeholders only.
- No secrets, raw PII, provider responses, API keys, private keys, or access tokens are committed.

## Commit Style

Use Conventional Commits:

- `feat:` for product behavior
- `fix:` for bug fixes
- `docs:` for documentation
- `test:` for tests
- `refactor:` for internal structure changes
- `security:` for security hardening
- `chore:` for maintenance

## Review Standard

Reviewers should check correctness, privacy impact, policy safety, legal overclaim risk, cross-chain validation, test coverage, and whether the change makes the future public repository more trustworthy.

## License

By contributing, you agree that your contributions will be licensed under the repository's license once one is selected.