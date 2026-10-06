// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ComplianceTypes} from "./ComplianceTypes.sol";

/**
 * @title CompliancePayload
 * @notice The single definition of the cross-chain compliance message, shared by
 *         {CrossChainComplianceSender} and {CrossChainComplianceReceiver}.
 *
 * @dev ## Why one definition
 *
 *      Sender and receiver must agree byte-for-byte on the wire format. When that
 *      format lives in two contracts it drifts: a field is added on one side and the
 *      other silently mis-decodes, or `abi.decode` reverts deep inside a callback
 *      where attribution is hard. Defining it once removes that failure mode.
 *
 * @dev ## What is deliberately absent
 *
 *      `subjectCommitment` is **not** in the payload. The destination needs to
 *      answer "does a valid credential exist for this CCID", and the CCID already
 *      binds it. Shipping the commitment would publish a second, correlatable value
 *      per holder on every destination chain for no functional gain.
 *
 * @dev ## Integrity
 *
 *      The receiver cannot re-derive the CCID - doing so would require the
 *      commitment, which we refuse to transmit. Integrity is established instead by
 *      {bindingHash}: the sender commits to the message contents, the receiver
 *      recomputes and rejects any mismatch.
 *
 *      With the router check, the sender allowlist, and monotonic nonces, the
 *      destination learns three independent facts: the message arrived via CCIP,
 *      from a permitted sender, and describes exactly the CCID and state it claims.
 */
library CompliancePayload {
    /// @notice Domain separator for the binding hash, versioned independently.
    bytes32 internal constant PAYLOAD_DOMAIN = keccak256("rwa-compliance-gateway/propagation/v1");

    /**
     * @dev Encoded length: 13 static 32-byte words.
     *
     *      Counted against {encode}, not guessed. A mismatch here would make every
     *      inbound message fail the length guard, so
     *      `test/CompliancePayload.t.sol` asserts the constant equals the real
     *      encoded size rather than trusting this comment.
     */
    uint256 internal constant ENCODED_LENGTH = 416;

    /**
     * @notice Why a payload failed to decode.
     * @dev Distinguished so the receiver can report `MalformedPayload` for a bad
     *      length (suggests a version mismatch) and `UnknownStatus` for an
     *      out-of-range enum (suggests a sender bug). Operators act on those
     *      differently, so collapsing them loses information.
     */
    enum DecodeError {
        None,
        BadLength,
        NumericOverflow,
        UnknownStatus,
        UnknownClass
    }

    /// @notice The decoded propagation message.
    struct Message {
        bytes32 ccid;
        bytes32 credentialType;
        bytes32 providerId;
        bytes32 evidenceHash;
        uint32 schemaVersion;
        uint16 jurisdictionCode;
        uint64 issuedAt;
        uint64 expiresAt;
        uint64 nonce;
        uint8 status;
        uint8 investorClass;
        uint64 sourceChainSelector;
        bytes32 bindingHash;
    }

    /**
     * @notice Commit to a message's contents.
     */
    function computeBindingHash(
        bytes32 ccid,
        bytes32 credentialType,
        bytes32 providerId,
        bytes32 evidenceHash,
        uint32 schemaVersion,
        uint16 jurisdictionCode,
        ComplianceTypes.InvestorClass investorClass,
        uint64 issuedAt,
        uint64 expiresAt,
        uint64 nonce,
        ComplianceTypes.CredentialStatus status,
        uint64 sourceChainSelector
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                PAYLOAD_DOMAIN,
                ccid,
                credentialType,
                providerId,
                evidenceHash,
                uint256(schemaVersion),
                uint256(jurisdictionCode),
                uint8(investorClass),
                issuedAt,
                expiresAt,
                nonce,
                uint8(status),
                sourceChainSelector
            )
        );
    }

    /// @notice Recompute a received message's binding hash for comparison.
    function recomputeBindingHash(Message memory m) internal pure returns (bytes32) {
        return computeBindingHash(
            m.ccid,
            m.credentialType,
            m.providerId,
            m.evidenceHash,
            m.schemaVersion,
            m.jurisdictionCode,
            ComplianceTypes.InvestorClass(m.investorClass),
            m.issuedAt,
            m.expiresAt,
            m.nonce,
            ComplianceTypes.CredentialStatus(m.status),
            m.sourceChainSelector
        );
    }

    /// @notice ABI-encode a message for CCIP transport.
    function encode(Message memory m) internal pure returns (bytes memory) {
        return abi.encode(
            m.ccid,
            m.credentialType,
            m.providerId,
            m.evidenceHash,
            uint256(m.schemaVersion),
            uint256(m.jurisdictionCode),
            m.issuedAt,
            m.expiresAt,
            m.nonce,
            m.status,
            m.investorClass,
            m.sourceChainSelector,
            m.bindingHash
        );
    }

    /**
     * @notice ABI-decode and structurally validate a message.
     * @dev Takes `bytes memory` so one implementation serves the receiver (calldata)
     *      and off-chain/test callers (memory). Returns a reason rather than
     *      reverting, so the caller can raise a precisely named error: a truncated
     *      payload otherwise surfaces as an opaque ABI revert from deep inside a
     *      CCIP callback, where attribution is difficult.
     *
     *      The length guard is what makes the single tuple decode safe: `abi.decode`
     *      of an all-static tuple requires an exact length, and a longer buffer
     *      would otherwise be accepted with trailing junk.
     */
    function decode(bytes memory data) internal pure returns (Message memory m, DecodeError err) {
        if (data.length != ENCODED_LENGTH) return (m, DecodeError.BadLength);

        uint256 schemaVersionRaw;
        uint256 jurisdictionCodeRaw;
        uint256 issuedAtRaw;
        uint256 expiresAtRaw;
        uint256 nonceRaw;
        uint256 statusRaw;
        uint256 classRaw;
        uint256 sourceChainRaw;

        (
            m.ccid,
            m.credentialType,
            m.providerId,
            m.evidenceHash,
            schemaVersionRaw,
            jurisdictionCodeRaw,
            issuedAtRaw,
            expiresAtRaw,
            nonceRaw,
            statusRaw,
            classRaw,
            sourceChainRaw,
            m.bindingHash
        ) =
            abi.decode(
                data,
                (
                    bytes32,
                    bytes32,
                    bytes32,
                    bytes32,
                    uint256,
                    uint256,
                    uint256,
                    uint256,
                    uint256,
                    uint256,
                    uint256,
                    uint256,
                    bytes32
                )
            );

        // Explicit bounds, so a maliciously wide word cannot wrap into a small
        // plausible value. `uint8` checks are redundant given the enum checks below -
        // `Revoked` is 5 and `Blocked` is 3 - but they are kept so the reason code is
        // unambiguous about *why* a value was rejected.
        if (schemaVersionRaw > type(uint32).max) return (m, DecodeError.NumericOverflow);
        if (jurisdictionCodeRaw > type(uint16).max) return (m, DecodeError.NumericOverflow);
        if (issuedAtRaw > type(uint64).max) return (m, DecodeError.NumericOverflow);
        if (expiresAtRaw > type(uint64).max) return (m, DecodeError.NumericOverflow);
        if (nonceRaw > type(uint64).max) return (m, DecodeError.NumericOverflow);
        if (sourceChainRaw > type(uint64).max) return (m, DecodeError.NumericOverflow);
        if (statusRaw > type(uint8).max) return (m, DecodeError.NumericOverflow);
        if (classRaw > type(uint8).max) return (m, DecodeError.NumericOverflow);

        // Enum range checks MUST precede the conversion: Solidity panics on an
        // out-of-range enum conversion, which would turn malformed input into an
        // unhandled panic rather than a named, actionable error.
        if (statusRaw > uint256(ComplianceTypes.CredentialStatus.Revoked)) return (m, DecodeError.UnknownStatus);
        if (classRaw > uint256(ComplianceTypes.InvestorClass.Blocked)) return (m, DecodeError.UnknownClass);

        m.schemaVersion = uint32(schemaVersionRaw);
        m.jurisdictionCode = uint16(jurisdictionCodeRaw);
        m.issuedAt = uint64(issuedAtRaw);
        m.expiresAt = uint64(expiresAtRaw);
        m.nonce = uint64(nonceRaw);
        m.status = uint8(statusRaw);
        m.investorClass = uint8(classRaw);
        m.sourceChainSelector = uint64(sourceChainRaw);

        err = DecodeError.None;
    }

    /// @notice True when the payload's status is a legal enum member.
    function isKnownStatus(Message memory m) internal pure returns (bool) {
        return uint256(m.status) <= uint256(ComplianceTypes.CredentialStatus.Revoked);
    }

    /// @notice True when the payload's investor class is a legal enum member.
    function isKnownClass(Message memory m) internal pure returns (bool) {
        return uint256(m.investorClass) <= uint256(ComplianceTypes.InvestorClass.Blocked);
    }
}
