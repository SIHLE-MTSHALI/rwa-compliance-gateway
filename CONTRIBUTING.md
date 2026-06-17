# Contributing

Thank you for contributing to this project. This document outlines standards and processes.

## Code of Conduct

- Be respectful and constructive
- Focus on the technical merits of contributions
- No harassment, discrimination, or unprofessional behavior

## Development Standards

This project follows **Crypto/Money Software Development Standards — Mid-2026**. Key requirements:

### Smart Contracts (Solidity)
- **Foundry** as primary development framework
- **Solidity 0.8.30+** with pinned compiler version
- **Full NatSpec** on all public/external functions (CI-enforced)
- **CEI pattern** in every state-changing function
- **ReentrancyGuardTransient** on all external-call functions
- **AccessControl** (not Ownable) for permission management
- ≥90% line coverage, ≥80% branch coverage

### CRE Workflows
- TypeScript or Go compiled to WebAssembly
- Always use `bigint` for on-chain values
- Use `runtime.now()` not `Date.now()`
- Secrets via Vault DON — never plaintext `.env` for production

### Testing Requirements
- Unit tests for every public/external function
- Edge cases (zero, one, type(uint256).max, empty arrays)
- Fuzz tests on all financial calculations
- Invariant tests
- Fork tests for cross-chain and upgrade validation

## Pull Request Process

1. **Fork** the repository
2. **Create** a feature branch (`feat/description` or `fix/description`)
3. **Write** tests that cover your changes
4. **Ensure** CI passes:
   - `forge fmt --check`
   - `slither .` + `aderyn .`
   - `forge test -vvv`
   - `forge snapshot --check --tolerance 5`
   - `forge coverage --report lcov` (≥90%)
5. **Document** any new public interfaces with NatSpec
6. **Update** gas snapshots if gas profile changes
7. **Open** a PR with a clear description and linked issue

## Commit Conventions

- `feat:` — new feature
- `fix:` — bug fix
- `docs:` — documentation
- `test:` — tests
- `refactor:` — code restructuring
- `perf:` — performance improvement
- `security:` — security-related changes
- `chore:` — maintenance

## Review Standards

- At least **1 approving review** required
- **No pending change requests**
- **All CI checks green**
- Reviewer verifies: security implications, gas impact, test coverage, NatSpec completeness

## License

By contributing, you agree that your contributions will be licensed under the project's license.

---

*For questions, open a Discussion or reach out on Discord.*
