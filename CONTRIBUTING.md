# Contributing to RWA Compliance Gateway

Thank you for helping improve RWA Compliance Gateway. This project is intended to become practical, production-grade compliance infrastructure for tokenized real-world asset access, not a prototype.

## Current Stage

The repository is in product and architecture design. Treat `PRD.md` as the canonical product specification and `ENGINEERING_SPEC.md` as the engineering build contract.

Do not add claims about production investor onboarding, legal or regulatory approval, live RWA pools, completed audits, Chainlink endorsement, bug bounties, or provider partnerships unless there is verifiable evidence in the repository.

## Contribution Focus

High-value contributions improve the full product path:

- Credential lifecycle: issue, renew, suspend, expire, revoke, review, and propagation.
- Provider registry, schema support, provider health, and adapter boundaries.
- Pool policy design for jurisdiction, investor class, freshness, allocation caps, and manual review.
- Chainlink verification, renewal, revocation, and provider-health workflows.
- CCID binding, CCIP propagation, destination freshness, and reason-coded access checks.
- Investor portal, issuer dashboard, auditor exports, operations runbooks, and threat-model coverage.

## Product Quality Bar

- Build toward the production compliance network described in `PRD.md`.
- Use staged release gates for safety, not reduced product ambition.
- Never store or emit raw PII, documents, tax IDs, beneficial owner data, provider reports, names, emails, or phone numbers.
- Legal claims require external legal review.
- Keep docs aligned with the full product PRD, engineering spec, and production readiness gates.

## Verification Expectations

| Change type | Expected verification |
| --- | --- |
| Docs only | Check terminology, links, and alignment with `PRD.md` and `ENGINEERING_SPEC.md` |
| Contracts | Formatting, unit tests, fuzz tests, and relevant invariant tests |
| Policy logic | Tests for allow, deny, review, allocation caps, jurisdiction rules, expiry, suspension, and revocation |
| Workflows | Tests for provider pass, fail, manual review, timeout, malformed response, provider pause, and revocation |
| CCIP flows | Tests for propagation, replay, wrong source, stale nonce, and destination freshness |

If a check cannot run, document the blocker in the PR.

## Pull Request Checklist

- Change maps to `PRD.md` or `ENGINEERING_SPEC.md`.
- Public docs avoid fake deployments, fake provider claims, fake legal approvals, fake audits, fake bounty details, and production onboarding claims.
- Privacy-sensitive changes state what data is processed, stored, emitted, logged, and intentionally excluded.
- Tests or verification notes cover the behavior changed.
- New environment variables use placeholders only.
- No secrets, raw PII, provider responses, API keys, private keys, or access tokens are committed.

## Commit Style

Use Conventional Commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `security:`, or `chore:`.

## License

By contributing, you agree that your contributions will be licensed under the repository's license once one is selected.
