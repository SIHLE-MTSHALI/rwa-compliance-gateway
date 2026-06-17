# RWA Compliance Gateway

Privacy-conscious compliance automation for tokenized real-world asset pools: verify once, evaluate policy everywhere, and keep raw investor identity data off public chain state.

## Status

This repository is in product and architecture design. The canonical product specification is [PRD.md](./PRD.md). Implementation work should follow the PRD requirements, privacy constraints, verification plan, and launch criteria before any production or regulatory claims are made.

## Why It Exists

RWA platforms need KYC/KYB, sanctions checks, accreditation, jurisdiction rules, allocation limits, and ongoing monitoring. Rebuilding that pipeline in every platform creates repeated investor onboarding, duplicated PII exposure, inconsistent policy enforcement, and slow capital deployment.

RWA Compliance Gateway defines a shared compliance credential and policy layer for issuers and investors, with issuer-configured rules and cross-chain credential propagation.

## Product Shape

1. Investor completes verification with a supported off-chain provider.
2. Chainlink CRE coordinates verification and lifecycle workflows.
3. Confidential compute is used as the sensitive processing boundary where supported.
4. Credential registry stores minimal credential state, expiry, status, and evidence hashes.
5. Issuers configure pool-specific compliance policies.
6. Pools call an access module that returns allow, deny, or review-required with reason codes.
7. CCIP propagates credential state to supported chains.
8. Automation manages expiry, renewal, and scheduled checks.

## Core Design Goals

- Raw investor PII must not be stored in on-chain state or events.
- Pool policies must be explicit, versioned, and auditable.
- Manual review must be a valid state, not an accidental allow.
- Cross-chain credential freshness must be visible to issuers and investors.
- Docs must describe architecture and assumptions, not promise legal compliance.

## Planned Architecture

| Layer | Responsibility |
| --- | --- |
| Compliance gateway | CRE result intake and lifecycle coordination |
| Credential registry | Status, expiry, evidence hash, revocation state |
| Pool policy manager | Issuer-configured rules and policy versions |
| Pool compliance module | Access evaluation and reason codes |
| Provider registry | Supported KYC/KYB provider adapters |
| CCIP sender/receiver | Cross-chain credential propagation |
| Automation workflows | Expiry, renewal, and revocation scheduling |

## Documentation

- [PRD.md](./PRD.md) - canonical product requirements, workflows, architecture, privacy model, risks, verification, and launch criteria.
- [ENGINEERING_SPEC.md](./ENGINEERING_SPEC.md) - implementation-ready build contract with MVP decisions, contract surfaces, workflow I/O, tests, milestones, and definition of done.
- [PRODUCT_REQUIREMENTS_DOC.md](./PRODUCT_REQUIREMENTS_DOC.md) - compatibility pointer to the canonical PRD.

## Implementation Notes

The first implementation should prove one provider adapter, one source chain, one destination chain, and one sample RWA pool with allow, deny, and review-required states. Any compliance or regulatory positioning should be reviewed with qualified counsel before public launch.

## Security and Privacy Posture

This repository is privacy-sensitive and compliance-sensitive. Before public testnet, it needs no-PII storage tests, policy-deny tests, revocation and expiry invariants, CCIP replay tests, secret scanning, static analysis, and documentation that explains immutable-chain limitations.

## Chainlink References

- CRE: https://docs.chain.link/cre
- CCIP: https://docs.chain.link/ccip
- Automation: https://docs.chain.link/chainlink-automation
- Proof of Reserve: https://docs.chain.link/data-feeds/proof-of-reserve

## License

MIT. See [LICENSE](./LICENSE).
