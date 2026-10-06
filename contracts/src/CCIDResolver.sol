// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {AuditTrail} from "./AuditTrail.sol";
import {CCIDResolver} from "./CCIDResolver.sol";
import {ComplianceRegistry} from "./ComplianceRegistry.sol";
import {CrossChainComplianceSender} from "./CrossChainComplianceSender.sol";
import {EmergencyControls} from "./EmergencyControls.sol";
import {ProviderRegistry} from "./ProviderRegistry.sol";
import {ComplianceTypes} from "./libraries/ComplianceTypes.sol";

/**
 * @title CCIDResolver
 * @notice Derives and verifies compliance credential content identifiers.
 *
 * @dev ## What a CCID is
 *
 *      A CCID is a credential's **identity binding**: "this attestation of this
 *      attribute, by this provider, under this schema, for this jurisdiction and
 *      eligibility class, belongs to this holder".
 *
 *      The `nonce` is deliberately **not** part of it. A CCID is what integrators
 *      and holders store, and what propagates across chains. If renewal produced a
 *      new CCID, every renewal would strand the previous credential on every
 *      destination chain as a dangling, still-`Valid` record - unreachable by any
 *      revocation, because nothing knows its new name.
 *
 *      Replay protection is the `nonce`, which lives on the record and must strictly
 *      increase. Keeping the two concerns separate is what makes both correct.
 *
 * @dev ## Why jurisdiction and class are inputs
 *
 *      Including them in the derivation means a holder cannot present a US
 *      accredited attestation as though it were a UK professional one. Both are
 *      coarse buckets rather than identity, so binding them costs no privacy.
 *
 * @dev ## Privacy
 *
 *      The holder enters only as `subjectCommitment`, computed **off-chain** as a
 *      salted commitment (e.g. `keccak256(salt || verifiedAttribute)`). The salt
 *      never reaches the chain, so the commitment is neither reversible nor
 *      correlatable across issuers that choose different salts.
 *
 *      There is deliberately no function here that accepts a name, email, or
 *      document: the sensitive boundary is off-chain by construction, not by policy.
 */
contract CCIDResolver {
    /// @notice Domain separator, versioned so future rules cannot collide.
    bytes32 public constant DOMAIN = keccak256("rwa-compliance-gateway/CCID/v1");

    event CCIDDerived(bytes32 indexed ccid, bytes32 indexed credentialType, bytes32 indexed providerId);

    /**
     * @notice Deterministically derive the CCID for a credential.
     * @dev Field order is part of the protocol and is frozen alongside `DOMAIN`.
     *      Explicit `uint256` widening is required: `abi.encodePacked` would
     *      silently truncate the `uint32`/`uint64`/`uint16` inputs and let two
     *      distinct credentials collide.
     */
    function compute(
        bytes32 credentialType,
        uint32 schemaVersion,
        bytes32 providerId,
        uint16 jurisdictionCode,
        ComplianceTypes.InvestorClass investorClass,
        bytes32 subjectCommitment
    ) public pure returns (bytes32 ccid) {
        ccid = keccak256(
            abi.encode(
                DOMAIN,
                credentialType,
                uint256(schemaVersion),
                providerId,
                uint256(jurisdictionCode),
                uint8(investorClass),
                subjectCommitment
            )
        );
    }

    /// @notice Derive and emit, for use inside transactions that mint a CCID.
    function derive(
        bytes32 credentialType,
        uint32 schemaVersion,
        bytes32 providerId,
        uint16 jurisdictionCode,
        ComplianceTypes.InvestorClass investorClass,
        bytes32 subjectCommitment
    ) external returns (bytes32 ccid) {
        ccid = compute(credentialType, schemaVersion, providerId, jurisdictionCode, investorClass, subjectCommitment);
        emit CCIDDerived(ccid, credentialType, providerId);
    }

    /**
     * @notice Check a claimed CCID against the fields it must derive from.
     * @dev The anti-tampering primitive. A result whose `ccid` does not reproduce
     *      from its own fields is rejected by {ComplianceGateway}.
     */
    function verify(
        bytes32 ccid,
        bytes32 credentialType,
        uint32 schemaVersion,
        bytes32 providerId,
        uint16 jurisdictionCode,
        ComplianceTypes.InvestorClass investorClass,
        bytes32 subjectCommitment
    ) external pure returns (bool ok) {
        ok = ccid
            == compute(credentialType, schemaVersion, providerId, jurisdictionCode, investorClass, subjectCommitment);
    }

    /**
     * @notice Structural validation of the derivation inputs.
     * @dev A zero `subjectCommitment` would leave the credential unbound, which is
     *      worse than not issuing it at all.
     */
    function validateParts(bytes32 credentialType, bytes32 providerId, bytes32 subjectCommitment)
        external
        pure
        returns (bool ok)
    {
        ok = credentialType != bytes32(0) && providerId != bytes32(0) && subjectCommitment != bytes32(0);
    }

    /// @notice True for a jurisdiction code that is set.
    function isKnownJurisdiction(uint16 jurisdictionCode) external pure returns (bool) {
        return jurisdictionCode != 0;
    }

    /// @notice True for an investor class other than `Unknown` and `Blocked`.
    /// @dev `Blocked` is a real class, not an unknown one, so it is excluded here
    ///      deliberately: this predicate answers "does this credential assert an
    ///      eligibility class at all".
    function assertsEligibility(ComplianceTypes.InvestorClass cls) external pure returns (bool) {
        return
            cls == ComplianceTypes.InvestorClass.USAccredited || cls == ComplianceTypes.InvestorClass.NonUSProfessional;
    }
}
