// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ComplianceTypes} from "./libraries/ComplianceTypes.sol";

/**
 * @title ComplianceRegistry
 * @notice The only persistent home of compliance credential state.
 *
 * @dev ## Writer model
 *
 *      Holds no admin keys. Written by exactly two authorized writers:
 *
 *      1. `ComplianceGateway` - source of truth on the issuing chain.
 *      2. `CrossChainCredentialReceiver` - records replicas arriving via CCIP.
 *
 *      Splitting authority means a compromised gateway cannot forge destination
 *      state, and a compromised receiver cannot invent issuance.
 *
 * @dev ## Expiry without a keeper
 *
 *      {statusOf} applies expiry lazily from `expiresAt`, so a credential is
 *      denied the instant it lapses whether or not {expireDue} has run. A system
 *      whose expiry depended on a keeper being alive fails **open** the moment
 *      that keeper stalls, which is the one unacceptable direction for a
 *      compliance control. The sweeper exists to complete the event trail.
 *
 * @dev ## Allocation is deliberately absent
 *
 *      This registry stores no allocation. `PoolComplianceModule` takes the
 *      holder's current allocation as an argument rather than reading it, because
 *      allocation lives in the pool's own accounting and duplicating it here
 *      would create two sources of truth that drift.
 */
contract ComplianceRegistry {
    using ComplianceTypes for bytes32;

    /// @dev May mutate credential state.
    bytes32 public constant WRITER_ROLE = keccak256("WRITER_ROLE");

    /// @dev May change the writer set.
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    event CredentialIssued(
        bytes32 indexed ccid,
        bytes32 indexed credentialType,
        bytes32 indexed providerId,
        uint32 schemaVersion,
        uint16 jurisdictionCode,
        ComplianceTypes.InvestorClass investorClass,
        uint64 expiresAt,
        uint64 nonce
    );
    event CredentialStatusChanged(
        bytes32 indexed ccid,
        ComplianceTypes.CredentialStatus previous,
        ComplianceTypes.CredentialStatus current,
        bytes32 reason
    );
    event CredentialRenewed(bytes32 indexed ccid, uint64 previousExpiresAt, uint64 newExpiresAt, uint64 nonce);
    event CredentialPropagated(bytes32 indexed ccid, uint64 indexed sourceChainSelector, uint64 sourceNonce);
    event CredentialExpired(bytes32 indexed ccid, uint64 expiresAt);
    event WriterAuthorizationChanged(address indexed writer, bool authorized, address indexed changedBy);

    /// @dev ccid => ComplianceCredential
    mapping(bytes32 => ComplianceTypes.ComplianceCredential) private _records;

    /// @dev ccid => PropagationState. Kept out of the record so the struct
    ///      matches `ENGINEERING_SPEC.md` section 4 exactly.
    mapping(bytes32 => ComplianceTypes.PropagationState) private _propagation;

    error NotWriter(address caller);
    error NotAdmin(address caller);
    error CredentialNotFound(bytes32 ccid);
    error CredentialAlreadyExists(bytes32 ccid);
    error IllegalTransition(bytes32 ccid, ComplianceTypes.CredentialStatus from, ComplianceTypes.CredentialStatus to);
    error NonceNotIncreasing(bytes32 ccid, uint64 current, uint64 submitted);
    error ExpiryNotLater(uint64 current, uint64 submitted);
    error ZeroAddress();
    error BatchTooLarge(uint256 length);

    /// @dev Max records per sweep, to bound automation gas.
    uint256 public constant MAX_SWEEP_BATCH = 100;

    constructor(address admin) {
        if (admin == address(0)) revert ZeroAddress();
        _grantRole(ADMIN_ROLE, admin);
    }

    // ---------------------------------------------------------------------
    // Roles
    // ---------------------------------------------------------------------

    /// @dev Two roles do not justify a general-purpose authorisation system, and
    ///      the smaller bespoke surface is easier to audit.
    mapping(bytes32 => mapping(address => bool)) private _roles;

    function _grantRole(bytes32 role, address account) private {
        _roles[role][account] = true;
        if (role == WRITER_ROLE) emit WriterAuthorizationChanged(account, true, msg.sender);
    }

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role][account];
    }

    function setWriter(address writer, bool authorized) external {
        if (!hasRole(ADMIN_ROLE, msg.sender)) revert NotAdmin(msg.sender);
        if (writer == address(0)) revert ZeroAddress();
        if (_roles[WRITER_ROLE][writer] == authorized) return;
        // Emits immediately below; the lint heuristic cannot associate a
        // non-"role"-named event with this mapping.
        // forge-lint: disable-next-line(missing-events-access-control)
        _roles[WRITER_ROLE][writer] = authorized;
        emit WriterAuthorizationChanged(writer, authorized, msg.sender);
    }

    function isWriter(address account) external view returns (bool) {
        return hasRole(WRITER_ROLE, account);
    }

    modifier onlyWriter() {
        if (!hasRole(WRITER_ROLE, msg.sender)) revert NotWriter(msg.sender);
        _;
    }

    // ---------------------------------------------------------------------
    // Writes
    // ---------------------------------------------------------------------

    /**
     * @notice Write a new credential. Rejects any pre-existing CCID.
     */
    function issue(
        bytes32 ccid,
        bytes32 credentialType,
        bytes32 providerId,
        bytes32 evidenceHash,
        uint32 schemaVersion,
        uint16 jurisdictionCode,
        ComplianceTypes.InvestorClass investorClass,
        uint64 issuedAt,
        uint64 expiresAt,
        uint64 nonce
    ) external onlyWriter {
        if (_records[ccid].ccid != bytes32(0)) revert CredentialAlreadyExists(ccid);

        ComplianceTypes.ComplianceCredential storage r = _records[ccid];
        r.ccid = ccid;
        r.credentialType = credentialType;
        r.providerId = providerId;
        r.evidenceHash = evidenceHash;
        r.schemaVersion = schemaVersion;
        r.jurisdictionCode = jurisdictionCode;
        r.investorClass = investorClass;
        r.status = ComplianceTypes.CredentialStatus.Valid;
        r.issuedAt = issuedAt;
        r.expiresAt = expiresAt;
        r.updatedAt = uint64(block.timestamp);
        r.nonce = nonce;

        emit CredentialIssued(
            ccid, credentialType, providerId, schemaVersion, jurisdictionCode, investorClass, expiresAt, nonce
        );
    }

    /**
     * @notice Open a credential in `Pending` while verification is in flight.
     * @dev Lets a holder see "your check is running" instead of being
     *      indistinguishable from a credential that was never requested.
     *      `Pending` denies access; it is not a provisional allow.
     */
    function registerPending(bytes32 ccid, bytes32 credentialType, uint32 schemaVersion, uint64 expiresAt)
        external
        onlyWriter
    {
        if (_records[ccid].ccid != bytes32(0)) revert CredentialAlreadyExists(ccid);

        ComplianceTypes.ComplianceCredential storage r = _records[ccid];
        r.ccid = ccid;
        r.credentialType = credentialType;
        r.providerId = bytes32(0);
        r.evidenceHash = bytes32(0);
        r.schemaVersion = schemaVersion;
        r.jurisdictionCode = 0;
        r.investorClass = ComplianceTypes.InvestorClass.Unknown;
        r.status = ComplianceTypes.CredentialStatus.Pending;
        r.issuedAt = uint64(block.timestamp);
        r.expiresAt = expiresAt;
        r.updatedAt = uint64(block.timestamp);
        r.nonce = 0;

        emit CredentialStatusChanged(
            ccid,
            ComplianceTypes.CredentialStatus.Unknown,
            ComplianceTypes.CredentialStatus.Pending,
            ComplianceTypes.REASON_PENDING
        );
    }

    /**
     * @notice Resolve a `Pending` credential into a verified one.
     * @dev Separate from {issue} because the record already exists, and a holder
     *      who started a check must be able to finish it.
     */
    function resolvePending(
        bytes32 ccid,
        bytes32 providerId,
        bytes32 evidenceHash,
        uint32 schemaVersion,
        uint16 jurisdictionCode,
        ComplianceTypes.InvestorClass investorClass,
        uint64 issuedAt,
        uint64 expiresAt,
        uint64 nonce
    ) external onlyWriter {
        ComplianceTypes.ComplianceCredential storage r = _records[ccid];
        if (r.ccid == bytes32(0)) revert CredentialNotFound(ccid);
        if (r.status != ComplianceTypes.CredentialStatus.Pending) revert CredentialAlreadyExists(ccid);
        if (nonce <= r.nonce) revert NonceNotIncreasing(ccid, r.nonce, nonce);

        r.providerId = providerId;
        r.evidenceHash = evidenceHash;
        r.schemaVersion = schemaVersion;
        r.jurisdictionCode = jurisdictionCode;
        r.investorClass = investorClass;
        r.issuedAt = issuedAt;
        r.expiresAt = expiresAt;
        r.updatedAt = uint64(block.timestamp);
        r.nonce = nonce;
        r.status = ComplianceTypes.CredentialStatus.Valid;

        emit CredentialIssued(
            ccid, r.credentialType, providerId, schemaVersion, jurisdictionCode, investorClass, expiresAt, nonce
        );
    }

    /**
     * @notice Write a replica received from another chain.
     */
    function applyReplica(
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
    ) external onlyWriter {
        ComplianceTypes.ComplianceCredential storage r = _records[ccid];
        r.ccid = ccid;
        r.credentialType = credentialType;
        r.providerId = providerId;
        r.evidenceHash = evidenceHash;
        r.schemaVersion = schemaVersion;
        r.jurisdictionCode = jurisdictionCode;
        r.investorClass = investorClass;
        r.issuedAt = issuedAt;
        r.expiresAt = expiresAt;
        r.updatedAt = uint64(block.timestamp);
        r.nonce = nonce;
        r.status = status;

        ComplianceTypes.PropagationState storage p = _propagation[ccid];
        p.isReplica = true;
        p.sourceChainSelector = sourceChainSelector;
        p.lastUpdatedAt = uint64(block.timestamp);
        p.lastSourceNonce = nonce;

        emit CredentialPropagated(ccid, sourceChainSelector, nonce);
    }

    /**
     * @notice Move a credential to a new status.
     * @dev Enforces the transition table and bumps the nonce on every accepted
     *      transition. The bump is essential: the nonce is what a destination uses
     *      to judge an inbound message newer than what it holds. Without it, a
     *      revocation would carry the same nonce as the issuance it reverses and
     *      every destination would discard it as stale - leaving a revoked
     *      credential valid everywhere.
     */
    function setStatus(bytes32 ccid, ComplianceTypes.CredentialStatus next, bytes32 reason) external onlyWriter {
        ComplianceTypes.ComplianceCredential storage r = _records[ccid];
        if (r.ccid == bytes32(0)) revert CredentialNotFound(ccid);

        ComplianceTypes.CredentialStatus previous = r.status;
        if (!_isTransitionAllowed(previous, next)) revert IllegalTransition(ccid, previous, next);

        r.status = next;
        r.updatedAt = uint64(block.timestamp);
        r.nonce += 1;

        emit CredentialStatusChanged(ccid, previous, next, reason);
    }

    /**
     * @notice Extend a credential after successful re-verification.
     * @dev Refreshes the nonce as well as the expiry, so renewal cannot be forged
     *      by replaying an older provider result.
     */
    function renew(bytes32 ccid, uint64 newExpiresAt, uint64 newNonce) external onlyWriter {
        ComplianceTypes.ComplianceCredential storage r = _records[ccid];
        if (r.ccid == bytes32(0)) revert CredentialNotFound(ccid);
        if (r.status == ComplianceTypes.CredentialStatus.Revoked) {
            revert IllegalTransition(ccid, r.status, ComplianceTypes.CredentialStatus.Valid);
        }
        if (newExpiresAt <= r.expiresAt) revert ExpiryNotLater(r.expiresAt, newExpiresAt);
        if (newNonce <= r.nonce) revert NonceNotIncreasing(ccid, r.nonce, newNonce);

        uint64 previousExpiresAt = r.expiresAt;
        r.expiresAt = newExpiresAt;
        r.nonce = newNonce;
        r.issuedAt = uint64(block.timestamp);
        r.updatedAt = uint64(block.timestamp);
        r.status = ComplianceTypes.CredentialStatus.Valid;

        emit CredentialRenewed(ccid, previousExpiresAt, newExpiresAt, newNonce);
    }

    /**
     * @notice Mark lapsed credentials `Expired`, emitting for each.
     * @dev Cosmetic for safety purposes: {statusOf} already denies on `expiresAt`.
     *      Exists so monitoring and audit exports see a clean terminal transition.
     */
    function expireDue(bytes32[] calldata ccids) external onlyWriter returns (uint256 expiredCount) {
        if (ccids.length > MAX_SWEEP_BATCH) revert BatchTooLarge(ccids.length);

        for (uint256 i = 0; i < ccids.length; ++i) {
            bytes32 ccid = ccids[i];
            ComplianceTypes.ComplianceCredential storage r = _records[ccid];
            if (r.ccid == bytes32(0)) continue;
            if (r.status == ComplianceTypes.CredentialStatus.Valid && r.expiresAt <= uint64(block.timestamp)) {
                r.status = ComplianceTypes.CredentialStatus.Expired;
                r.updatedAt = uint64(block.timestamp);
                ++expiredCount;
                emit CredentialExpired(ccid, r.expiresAt);
                emit CredentialStatusChanged(
                    ccid,
                    ComplianceTypes.CredentialStatus.Valid,
                    ComplianceTypes.CredentialStatus.Expired,
                    ComplianceTypes.REASON_EXPIRED
                );
            }
        }
    }

    // ---------------------------------------------------------------------
    // Reads
    // ---------------------------------------------------------------------

    function exists(bytes32 ccid) external view returns (bool) {
        return _records[ccid].ccid != bytes32(0);
    }

    /// @notice Raw stored record, with no lazy expiry applied.
    function getRecord(bytes32 ccid) external view returns (ComplianceTypes.ComplianceCredential memory) {
        return _records[ccid];
    }

    /// @notice Status with lazy expiry applied. The function policy paths should use.
    function statusOf(bytes32 ccid) public view returns (ComplianceTypes.CredentialStatus) {
        ComplianceTypes.ComplianceCredential storage r = _records[ccid];
        if (r.ccid == bytes32(0)) return ComplianceTypes.CredentialStatus.Unknown;
        if (r.status == ComplianceTypes.CredentialStatus.Valid && r.expiresAt <= uint64(block.timestamp)) {
            return ComplianceTypes.CredentialStatus.Expired;
        }
        return r.status;
    }

    /// @notice True only for a present, `Valid`, unexpired record.
    /// @dev Says nothing about provider status or pool policy. Those are policy
    ///      inputs, so an access decision needs {PoolComplianceModule}.
    function isValid(bytes32 ccid) external view returns (bool) {
        return statusOf(ccid) == ComplianceTypes.CredentialStatus.Valid;
    }

    function getPropagationState(bytes32 ccid) external view returns (ComplianceTypes.PropagationState memory) {
        return _propagation[ccid];
    }

    /// @notice Seconds since this record was last written. `type(uint64).max` if absent.
    function ageOf(bytes32 ccid) external view returns (uint64 age) {
        if (_records[ccid].ccid == bytes32(0)) return type(uint64).max;
        return uint64(block.timestamp) - _records[ccid].updatedAt;
    }

    // ---------------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------------

    /**
     * @dev The lifecycle transition table.
     *      - `Revoked` is terminal: no path back to `Valid`, so a revoked
     *        credential cannot be resurrected by a later or buggy workflow.
     *      - Nothing enters `Valid` except from a recoverable state.
     *      - `Unknown` is the absence of a record, not a lifecycle step.
     */
    function _isTransitionAllowed(ComplianceTypes.CredentialStatus from, ComplianceTypes.CredentialStatus to)
        private
        pure
        returns (bool)
    {
        if (from == to) return true;
        if (from == ComplianceTypes.CredentialStatus.Revoked) return false;

        if (from == ComplianceTypes.CredentialStatus.Unknown) {
            return to == ComplianceTypes.CredentialStatus.Pending || to == ComplianceTypes.CredentialStatus.Valid;
        }

        if (from == ComplianceTypes.CredentialStatus.Pending) {
            return to == ComplianceTypes.CredentialStatus.Valid || to == ComplianceTypes.CredentialStatus.Suspended
                || to == ComplianceTypes.CredentialStatus.Revoked;
        }

        if (from == ComplianceTypes.CredentialStatus.Valid) {
            return to == ComplianceTypes.CredentialStatus.Expired || to == ComplianceTypes.CredentialStatus.Suspended
                || to == ComplianceTypes.CredentialStatus.Revoked;
        }

        if (from == ComplianceTypes.CredentialStatus.Expired) {
            // Recovery only via renewal, which is an explicit `renew` call.
            return to == ComplianceTypes.CredentialStatus.Revoked;
        }

        // Suspended
        return to == ComplianceTypes.CredentialStatus.Valid || to == ComplianceTypes.CredentialStatus.Revoked
            || to == ComplianceTypes.CredentialStatus.Expired;
    }
}
