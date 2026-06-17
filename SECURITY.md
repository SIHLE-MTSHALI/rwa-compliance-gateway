# Security Policy

## Reporting a Vulnerability

**DO NOT file a public issue.** Security vulnerabilities must be reported privately.

- **Email:** security@chainlink-blueprints.dev
- **Immunefi:** [Bug Bounty Program Link] (coming soon)
- **Response time:** Acknowledgment within 24 hours, initial assessment within 72 hours
- **PGP Key:** Available upon request

## Scope

| In Scope | Out of Scope |
|---|---|
| Smart contracts in `contracts/src/` | Third-party dependencies |
| CRE workflows in `workflows/` | Front-end application |
| CCIP integration layer | Infrastructure/CI |
| Automation upkeeps | Social engineering |

## Severity Classification

| Severity | Examples | Reward Range |
|---|---|---|
| **Critical** | Direct theft of funds, permanent freezing, governance takeover | $50,000+ |
| **High** | Theft under specific conditions, oracle manipulation enabling >5% value extraction | $10,000–$50,000 |
| **Medium** | Denial-of-service on core functions, bypassing rate limits | $2,000–$10,000 |
| **Low** | Incorrect event emissions, gas inefficiencies | $500–$2,000 |
| **Informational** | Code style issues, documentation errors | Recognition |

## Responsible Disclosure

1. Provide a detailed report with steps to reproduce
2. Include a runnable Proof of Concept (PoC) — Foundry test strongly preferred
3. Allow 90 days for remediation before public disclosure
4. Do not exploit the vulnerability beyond what is necessary to demonstrate it
5. Do not access, modify, or delete user data

## Security Measures (This Repository)

This project follows **Crypto/Money Software Development Standards — Mid-2026**:

- Defense-in-depth reentrancy protection (CEI + Transient ReentrancyGuard + SafeERC20)
- Granular role-based access control (OpenZeppelin AccessControl, not Ownable)
- Multi-sig (Safe) + TimelockController for all admin actions
- Oracle manipulation protection (TWAP, staleness checks, deviation bounds)
- Emergency pause with separate guardian role
- Slither + Aderyn passing in CI on every PR
- ≥90% test coverage with fuzzing and invariant tests
- Formal verification for contracts holding >$10M TVL
- Bug bounty program on Immunefi
- Upgrade safety validation in CI (if upgradeable)

## Audit History

| Date | Auditor | Scope | Report |
|---|---|---|---|
| TBD | TBD | Full protocol | [Link] |

## Disclosure Policy

Vulnerabilities may be publicly disclosed 90 days after remediation, or earlier by mutual agreement. Credit is given to the reporter unless they request anonymity.

## Contact

- **Security Lead:** security@chainlink-blueprints.dev
- **Discord:** [Chainlink Blueprints Server]
- **Immunefi Profile:** [Link]

---

*This security policy was last updated June 17, 2026.*
