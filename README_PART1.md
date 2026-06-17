# RWA Compliance Gateway

[![Solidity](https://img.shields.io/badge/Solidity-0.8.30-blue)](https://soliditylang.org)
[![Foundry](https://img.shields.io/badge/Foundry-Test%20Suite-orange)](https://book.getfoundry.sh/)
[![Chainlink CRE](https://img.shields.io/badge/Chainlink-CRE--Native-375bd2)](https://chain.link/cross-chain)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Active Development](https://img.shields.io/badge/Status-Active_Development-brightgreen)]()
[![Coverage](https://img.shields.io/badge/Coverage-%E2%89%A590%25-success)]()
[![Immunefi Bug Bounty](https://img.shields.io/badge/Bug_Bounty-Immunefi_%2450K%2B-critical)](https://immunefi.com/)

> **Verify once. Invest anywhere.** Institutional RWA compliance automation -- one KYC/AML verification, universal access to all participating tokenized real-world asset pools across all supported chains.

---

## Status

**Active Development** -- Target: Q3 2026 launch. The RWA Compliance Gateway is currently in pre-production engineering sprint with a 7-9 week delivery timeline. All core smart contracts, CRE workflows, and ACE integrations are being built concurrently.

---

## Architecture Overview

```mermaid
flowchart TB
    subgraph Investor["Institutional Investor"]
        A[Institutional Investor]
    end

    subgraph KYC["KYC/AML Provider Layer"]
        B1[Persona]
        B2[Sumsub]
        B3[Jumio]
    end

    subgraph TEE["Chainlink Confidential Compute"]
        C[TEE Enclave - PII Processing - Only Hash Exits]
    end

    subgraph ACE["ACE - Automated Compliance Engine"]
        D1[CCID - Cross-Chain Identity]
        D2[IdentityManager - Lifecycle Ops]
        D3[PolicyManager - Per-Pool Rules]
    end

    subgraph Gateway["RWA Compliance Gateway"]
        E1[ComplianceGateway.sol]
        E2[CredentialRegistry.sol]
        E3[PoolComplianceModule.sol]
    end

    subgraph Pools["RWA Pools"]
        F1[Real Estate Pool]
        F2[Private Credit Pool]
        F3[Treasury Yield Pool]
        F4[...]
    end

    subgraph Support["Chainlink Services"]
        G1[Automation - Expiry and Renewal]
        G2[CCIP v2 - Cross-Chain Propagation]
        G3[Proof of Reserve - Pool Attestation]
    end

    A -->|1. Submit KYC Docs| B1 & B2 & B3
    B1 & B2 & B3 -->|2. Verification Result| C
    C -->|3. Compliance Credential Hash| E1
    E1 -->|4. Issue CCID Credential| D1
    D1 --> D2 --> D3
    E2 -->|5. Store On-Chain Record| D1
    D3 -->|6. Evaluate Access| E3
    E3 -->|7. Allow/Deny| F1 & F2 & F3 & F4
    G1 -->|Trigger Renewal| E2
    G2 -->|Propagate Credential| D1
    G3 -->|Attest Reserves| F1 & F2 & F3 & F4

    style TEE fill:#1a1a2e,stroke:#e94560,color:#ffffff
    style ACE fill:#16213e,stroke:#0f3460,color:#ffffff
    style Gateway fill:#0f3460,stroke:#375bd2,color:#ffffff
```
