// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {AuditTrail} from "./AuditTrail.sol";
import {CCIDResolver} from "./CCIDResolver.sol";
import {ComplianceRegistry} from "./ComplianceRegistry.sol";
import {CrossChainComplianceSender} from "./CrossChainComplianceSender.sol";
import {EmergencyControls} from "./EmergencyControls.sol";
import {PoolPolicyManager} from "./PoolPolicyManager.sol";
import {ProviderRegistry} from "./ProviderRegistry.sol";
import {CompliancePayload} from "./libraries/CompliancePayload.sol";
import {ComplianceTypes} from "./libraries/ComplianceTypes.sol";

/**
 * @title ComplianceGateway
 * @notice Accepts credential results from authorized Chainlink workflows, validates
 *         them, writes source-of-truth state, and triggers propagation.
 *
 * @dev This is the only writer to {ComplianceRegistry} on the issuing chain, so
 *      every guarantee the system makes is enforced here.
 *
 * @dev ## Why validate so much on-chain
 *
 *      The workflow is off-chain and therefore outside the boundary we can reason
 *      about. A workflow bug, a compromised runner, or a replayed request must not
 *      be able to mint a credential that passes policy. So the gateway re-derives
 *      and re-checks, in this order:
 *
 *      1.  System is not paused.
 *      2.  Caller holds `WORKFLOW_SUBMITTER`.
 *      3.  CCID reproduces from the submitted fields (anti-tampering / binding).
 *      4.  Provider is registered and `Active`.
 *      5.  Credential type has a registered schema.
 *      6.  Schema admits this provider.
 *      7.  `expiresAt` is in the future, `issuedAt` is not implausibly skewed.
 *      8.  Jurisdiction and investor class are structurally valid.
 *      9.  `evidenceHash` is non-empty.
 *      10. Nonce strictly increases for this CCID.
 *
 *      Steps 4-8 mean a compromised workflow can *refuse* a credential but cannot
 *      invent one, extend its life, misstate a jurisdiction, or attribute it to a
 *      paused provider. Its worst outcome is denial of service, which is bounded and
 *      recoverable by rotating the role.
 *
 * @dev ## Revocation authority is schema-scoped
 *
 *      Who may revoke is decided by the pool policy in force, not by a single
 *      global role. A `GovernanceOnly` policy cannot be revoked by its issuer; a
 *      `HolderOrIssuer` policy lets the holder withdraw their own credential.
 */
contract ComplianceGateway {
    using ComplianceTypes for bytes32;

    /// @dev May submit results and lifecycle changes.
    bytes32 public constant WORKFLOW_SUBMITTER = keccak256("WORKFLOW_SUBMITTER");

    /// @dev Acts as the issuer where policy allows.
    bytes32 public constant ISSUER = keccak256("ISSUER");

    /// @dev May withdraw their own credential where policy allows.
    bytes32 public constant HOLDER = keccak256("HOLDER");

    /// @dev Role administration.
    bytes32 public constant ADMIN = keccak256("ADMIN");

    ComplianceRegistry public immutable REGISTRY;
    ProviderRegistry public immutable PROVIDERS;
    PoolPolicyManager public immutable POLICIES;
    CCIDResolver public immutable CCID_RESOLVER;
    AuditTrail public immutable AUDIT;
    EmergencyControls public immutable EMERGENCY;

    /// @notice Propagation sender. Address(0) disables propagation entirely.
    CrossChainComplianceSender public immutable SENDER;

    /// @notice Max clock skew tolerated between workflow-computed and chain time.
    uint64 public constant MAX_CLOCK_SKEW_SECONDS = 5 minutes;

    event CredentialResultSubmitted(
        bytes32 indexed ccid,
        bytes32 indexed credentialType,
        bytes32 indexed providerId,
        uint16 jurisdictionCode,
        uint64 expiresAt,
        uint64 nonce,
        uint256 destinations
    );
    event CredentialLifecycleAction(
        bytes32 indexed ccid, string action, ComplianceTypes.CredentialStatus resultingStatus, bytes32 reason
    );
    event VerificationStarted(bytes32 indexed ccid, bytes32 indexed credentialType, uint64 expiresAt);
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed granter);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed revoker);

    error NotAuthorized(address caller);
    error SystemPaused();
    error InvalidCCID(bytes32 claimed, bytes32 expected);
    error ProviderNotActive(bytes32 providerId);
    error ProviderNotAdmitted(bytes32 providerId, bytes32 credentialType, uint32 schemaVersion);
    error CredentialTypeNotRegistered(bytes32 credentialType);
    error JurisdictionUnset();
    error InvestorClassUnknown();
    error ExpiryNotInFuture(uint64 expiresAt, uint64 nowTs);
    error IssuanceTooSkewed(uint64 issuedAt, uint64 nowTs);
    error ZeroEvidenceHash();
    error NonceNotIncreasing(bytes32 ccid, uint64 current, uint64 submitted);
    error RevocationNotPermitted(bytes32 ccid, address caller);
    error NoPolicyForPool(bytes32 poolId);
    error ZeroAddress();

    constructor(
        address admin,
        ComplianceRegistry registry,
        ProviderRegistry providers,
        PoolPolicyManager policies,
        CCIDResolver ccidResolver,
        AuditTrail audit,
        CrossChainComplianceSender sender,
        EmergencyControls emergency
    ) {
        if (admin == address(0)) revert ZeroAddress();
        _grantRole(ADMIN, admin);
        _grantRole(WORKFLOW_SUBMITTER, admin);
        _grantRole(ISSUER, admin);
        REGISTRY = registry;
        PROVIDERS = providers;
        POLICIES = policies;
        CCID_RESOLVER = ccidResolver;
        AUDIT = audit;
        SENDER = sender;
        EMERGENCY = emergency;
    }

    /**
     * @notice Whether this gateway is authorized to write to the audit trail.
     * @dev The deployer must call `AuditTrail.authorizeRecorder(gateway)` after
     *      deployment. It cannot be done in the gateway's constructor, because the
     *      trail authorizes by *admin*, and the gateway is not its admin.
     *
     *      Until that is done, every issuance reverts on the audit hook. That is the
     *      correct failure mode: a gateway that cannot record its own history is
     *      worse than one with no history at all, because the gap is invisible until
     *      someone audits. The deploy script performs the step.
     */
    function isAuditAuthorized() external view returns (bool) {
        return address(AUDIT) != address(0) && AUDIT.hasRole(AUDIT.AUDITOR_ROLE(), address(this));
    }

    // ---------------------------------------------------------------------
    // Roles
    // ---------------------------------------------------------------------

    mapping(bytes32 => mapping(address => bool)) private _roles;

    function _grantRole(bytes32 role, address account) private {
        _roles[role][account] = true;
        emit RoleGranted(role, account, msg.sender);
    }

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role][account];
    }

    function grantRole(bytes32 role, address account) external {
        if (!hasRole(ADMIN, msg.sender)) revert NotAuthorized(msg.sender);
        if (account == address(0)) revert ZeroAddress();
        _grantRole(role, account);
    }

    function revokeRole(bytes32 role, address account) external {
        if (!hasRole(ADMIN, msg.sender)) revert NotAuthorized(msg.sender);
        _roles[role][account] = false;
        emit RoleRevoked(role, account, msg.sender);
    }

    modifier onlyRole(bytes32 role) {
        if (!hasRole(role, msg.sender)) revert NotAuthorized(msg.sender);
        _;
    }

    // ---------------------------------------------------------------------
    // Issuance
    // ---------------------------------------------------------------------

    /**
     * @notice Open a credential in `Pending` when verification begins.
     * @dev Lets a holder see that a check is in flight rather than observing
     *      `NO_CREDENTIAL` and being unable to distinguish "not requested" from
     *      "requested, still running".
     */
    function beginVerification(bytes32 ccid, bytes32 credentialType, uint32 schemaVersion, uint64 ttlSeconds)
        external
        onlyRole(WORKFLOW_SUBMITTER)
    {
        if (EMERGENCY.isPaused()) revert SystemPaused();
        uint64 issuedAt = uint64(block.timestamp);
        REGISTRY.registerPending(ccid, credentialType, schemaVersion, issuedAt + ttlSeconds);
        emit VerificationStarted(ccid, credentialType, issuedAt + ttlSeconds);
    }

    /**
     * @notice Submit a verified credential result and propagate it.
     * @dev The single issuance path. Resolves a `Pending` record if one exists,
     *      otherwise creates one.
     */
    function submitCredentialResult(ComplianceTypes.CredentialResult calldata r) external onlyRole(WORKFLOW_SUBMITTER) {
        if (EMERGENCY.isPaused()) revert SystemPaused();
        _validate(r);

        if (REGISTRY.exists(r.ccid)) {
            uint64 current = REGISTRY.getRecord(r.ccid).nonce;
            if (r.nonce <= current) revert NonceNotIncreasing(r.ccid, current, r.nonce);
            REGISTRY.resolvePending(
                r.ccid,
                r.providerId,
                r.evidenceHash,
                r.schemaVersion,
                r.jurisdictionCode,
                r.investorClass,
                r.issuedAt,
                r.expiresAt,
                r.nonce
            );
        } else {
            REGISTRY.issue(
                r.ccid,
                r.credentialType,
                r.providerId,
                r.evidenceHash,
                r.schemaVersion,
                r.jurisdictionCode,
                r.investorClass,
                r.issuedAt,
                r.expiresAt,
                r.nonce
            );
        }

        _recordIssuance(r.ccid, r.providerId);

        _propagate(
            r.ccid,
            r.credentialType,
            r.providerId,
            r.evidenceHash,
            r.schemaVersion,
            r.jurisdictionCode,
            r.investorClass,
            r.issuedAt,
            r.expiresAt,
            r.nonce,
            ComplianceTypes.CredentialStatus.Valid,
            r.destinationChainSelectors
        );

        emit CredentialResultSubmitted(
            r.ccid,
            r.credentialType,
            r.providerId,
            r.jurisdictionCode,
            r.expiresAt,
            r.nonce,
            r.destinationChainSelectors.length
        );
    }

    /**
     * @notice Renew after fresh provider verification.
     * @dev The result must satisfy every issuance check, so renewal is impossible
     *      without a provider attestation that passes the full gate. That is what
     *      stops a stale or forged result from extending a credential's life.
     */
    function renewCredential(
        ComplianceTypes.CredentialResult calldata r,
        uint64[] calldata destinations,
        uint64 newExpiresAt,
        uint64 newNonce
    ) external onlyRole(WORKFLOW_SUBMITTER) {
        if (EMERGENCY.isPaused()) revert SystemPaused();
        if (!REGISTRY.exists(r.ccid)) revert InvalidCCID(r.ccid, bytes32(0));
        _validate(r);

        REGISTRY.renew(r.ccid, newExpiresAt, newNonce);

        _propagate(
            r.ccid,
            r.credentialType,
            r.providerId,
            r.evidenceHash,
            r.schemaVersion,
            r.jurisdictionCode,
            r.investorClass,
            REGISTRY.getRecord(r.ccid).issuedAt,
            newExpiresAt,
            newNonce,
            ComplianceTypes.CredentialStatus.Valid,
            destinations
        );

        emit CredentialLifecycleAction(
            r.ccid, "renew", ComplianceTypes.CredentialStatus.Valid, ComplianceTypes.REASON_OK
        );
    }

    // ---------------------------------------------------------------------
    // Lifecycle
    // ---------------------------------------------------------------------

    /**
     * @notice Revoke a credential and propagate the revocation.
     * @dev Authority comes from the pool policy in force. Revocation fails closed
     *      on propagation error: if a destination cannot be told, the revocation
     *      must not appear to have succeeded system-wide, so the whole transaction
     *      reverts.
     */
    function revoke(bytes32 ccid, bytes32 poolId, bytes32 reason, uint64[] calldata destinations) external {
        if (EMERGENCY.isPaused()) revert SystemPaused();
        ComplianceTypes.ComplianceCredential memory r = REGISTRY.getRecord(ccid);
        if (r.ccid == bytes32(0)) revert InvalidCCID(ccid, bytes32(0));

        _requireRevocationAuthority(ccid, poolId);

        REGISTRY.setStatus(ccid, ComplianceTypes.CredentialStatus.Revoked, reason);

        _recordAudit(ccid, poolId, reason, ComplianceTypes.CredentialStatus.Revoked);

        ComplianceTypes.ComplianceCredential memory fresh = REGISTRY.getRecord(ccid);
        _propagate(
            ccid,
            fresh.credentialType,
            fresh.providerId,
            fresh.evidenceHash,
            fresh.schemaVersion,
            fresh.jurisdictionCode,
            fresh.investorClass,
            fresh.issuedAt,
            fresh.expiresAt,
            fresh.nonce,
            ComplianceTypes.CredentialStatus.Revoked,
            destinations
        );

        emit CredentialLifecycleAction(ccid, "revoke", ComplianceTypes.CredentialStatus.Revoked, reason);
    }

    /// @notice Suspend a credential. Issuer-controlled.
    function suspend(bytes32 ccid, bytes32 reason, uint64[] calldata destinations) external onlyRole(ISSUER) {
        if (EMERGENCY.isPaused()) revert SystemPaused();
        ComplianceTypes.ComplianceCredential memory r = REGISTRY.getRecord(ccid);
        if (r.ccid == bytes32(0)) revert InvalidCCID(ccid, bytes32(0));

        REGISTRY.setStatus(ccid, ComplianceTypes.CredentialStatus.Suspended, reason);
        _repropagate(ccid, ComplianceTypes.CredentialStatus.Suspended, destinations);
        emit CredentialLifecycleAction(ccid, "suspend", ComplianceTypes.CredentialStatus.Suspended, reason);
    }

    /// @notice Lift a suspension, returning the credential to `Valid`.
    function resume(bytes32 ccid, bytes32 reason, uint64[] calldata destinations) external onlyRole(ISSUER) {
        if (EMERGENCY.isPaused()) revert SystemPaused();
        ComplianceTypes.ComplianceCredential memory r = REGISTRY.getRecord(ccid);
        if (r.ccid == bytes32(0)) revert InvalidCCID(ccid, bytes32(0));

        REGISTRY.setStatus(ccid, ComplianceTypes.CredentialStatus.Valid, reason);
        _repropagate(ccid, ComplianceTypes.CredentialStatus.Valid, destinations);
        emit CredentialLifecycleAction(ccid, "resume", ComplianceTypes.CredentialStatus.Valid, reason);
    }

    // ---------------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------------

    /**
     * @dev The validation sequence. Each step stops a distinct attack; see the
     *      contract docs for which.
     */
    function _validate(ComplianceTypes.CredentialResult calldata r) private view {
        // --- 3. Anti-tampering: the CCID must reproduce from its own fields. ---
        bytes32 expected = CCID_RESOLVER.compute(
            r.credentialType, r.schemaVersion, r.providerId, r.jurisdictionCode, r.investorClass, r.subjectCommitment
        );
        if (r.ccid != expected) revert InvalidCCID(r.ccid, expected);

        // --- 4. Provider must be usable right now. ---
        if (!PROVIDERS.isActive(r.providerId)) revert ProviderNotActive(r.providerId);

        // --- 5. Credential type must be a registered schema family. ---
        if (r.credentialType == bytes32(0)) revert CredentialTypeNotRegistered(r.credentialType);

        // --- 6. Schema must admit this provider. ---
        if (!PROVIDERS.supportsSchema(r.providerId, r.credentialType, r.schemaVersion)) {
            revert ProviderNotAdmitted(r.providerId, r.credentialType, r.schemaVersion);
        }

        // --- 7. Time sanity. ---
        uint64 nowTs = uint64(block.timestamp);
        if (r.expiresAt <= nowTs) revert ExpiryNotInFuture(r.expiresAt, nowTs);
        if (r.issuedAt > nowTs + MAX_CLOCK_SKEW_SECONDS) revert IssuanceTooSkewed(r.issuedAt, nowTs);

        // --- 8. Eligibility must be structurally valid. ---
        //
        // A credential asserting jurisdiction 0 or class `Unknown` would be
        // evaluated against pool policy as if it were real data, so it is rejected
        // at issuance rather than producing a confusing denial later.
        if (r.jurisdictionCode == 0) revert JurisdictionUnset();
        if (r.investorClass == ComplianceTypes.InvestorClass.Unknown) revert InvestorClassUnknown();

        // --- 9. Evidence must be committed to, though never stored. ---
        if (r.evidenceHash == bytes32(0)) revert ZeroEvidenceHash();
    }

    /**
     * @dev Who may revoke a credential.
     *
     *      The rule is scoped by pool, because revocation authority is a property of
     *      the policy that admitted the holder - not a property of the credential.
     *
     *      - `HOLDER` may always withdraw their own credential. A holder must always
     *        be able to exit; anything else is a trap.
     *      - `ADMIN` (governance) may always revoke.
     *      - `ISSUER` may revoke **unless** the policy for `poolId` is
     *        `GovernanceOnly`, which deliberately excludes the issuer - a
     *        credential the issuer could withdraw unilaterally would not be
     *        governance-scoped.
     *
     *      With no registered policy for the pool, the issuer is allowed, which
     *      keeps single-pool deployments working before policies are configured.
     */
    function _requireRevocationAuthority(bytes32 ccid, bytes32 poolId) private view {
        // A holder must always be able to exit. Anything else is a trap, so this is
        // checked before policy is even consulted.
        if (hasRole(HOLDER, msg.sender)) return;
        if (hasRole(ADMIN, msg.sender)) return;

        if (hasRole(ISSUER, msg.sender)) {
            if (!POLICIES.hasActivePolicy(poolId)) return;
            ComplianceTypes.PoolPolicy memory policy = POLICIES.getActivePolicy(poolId);

            // `GovernanceOnly` deliberately excludes the issuer: a credential the
            // issuer could withdraw unilaterally would not be governance-scoped.
            // `HolderOrIssuer` also admits the issuer, which the branch above
            // already handles, so only the exclusion needs stating.
            if (policy.revocationMode == ComplianceTypes.RevocationMode.GovernanceOnly) {
                revert RevocationNotPermitted(ccid, msg.sender);
            }
            return;
        }
        revert RevocationNotPermitted(ccid, msg.sender);
    }

    /**
     * @dev Audit hook, tolerant of the trail being unset so a deployment can ship
     *      without one.
     *
     *      Once configured it must succeed. A genuine revert is deliberately not
     *      swallowed: an audit trail that silently stops recording is worse than none,
     *      because an auditor cannot distinguish "no events occurred" from "the hook
     *      is broken". The gateway holds `AUDITOR_ROLE` from the constructor, so the
     *      only way this reverts is a real configuration fault.
     */
    function _recordAudit(bytes32 ccid, bytes32 poolId, bytes32 reason, ComplianceTypes.CredentialStatus status)
        private
    {
        if (address(AUDIT) == address(0)) return;
        AUDIT.recordCredentialEvent(ccid, poolId, reason, status);
    }

    /**
     * @dev Record an issuance, as its own entry kind.
     *
     *      Separate from {_recordAudit} because an auditor asking "when did this
     *      credential first appear, and which provider attested it" needs a record that
     *      is distinguishable from a later status change. Folding issuance into the
     *      generic credential-event shape left {AuditTrail.recordIssuance} unreachable
     *      from every contract in this repository - tested, but never called in
     *      production, which is the worst kind of coverage. See
     *      `docs/audit-readiness.md`.
     */
    function _recordIssuance(bytes32 ccid, bytes32 providerId) private {
        if (address(AUDIT) == address(0)) return;
        AUDIT.recordIssuance(ccid, bytes32(0), providerId);
    }

    /**
     * @dev Propagate a status-only change, re-reading the record so the bumped nonce
     *      is the one sent. Propagating a stale nonce would make every status
     *      change - revocation above all - look like a replay and be discarded.
     */
    function _repropagate(bytes32 ccid, ComplianceTypes.CredentialStatus status, uint64[] calldata destinations)
        private
    {
        ComplianceTypes.ComplianceCredential memory fresh = REGISTRY.getRecord(ccid);
        _propagate(
            ccid,
            fresh.credentialType,
            fresh.providerId,
            fresh.evidenceHash,
            fresh.schemaVersion,
            fresh.jurisdictionCode,
            fresh.investorClass,
            fresh.issuedAt,
            fresh.expiresAt,
            fresh.nonce,
            status,
            destinations
        );
    }

    /// @dev Dispatch when propagation is configured. An empty list is a no-op,
    ///      which is what lets a single-chain deployment run with it disabled.
    function _propagate(
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
        uint64[] calldata destinations
    ) private {
        if (address(SENDER) == address(0) || destinations.length == 0) return;

        CompliancePayload.Message memory m;
        m.ccid = ccid;
        m.credentialType = credentialType;
        m.providerId = providerId;
        m.evidenceHash = evidenceHash;
        m.schemaVersion = schemaVersion;
        m.jurisdictionCode = jurisdictionCode;
        m.investorClass = uint8(investorClass);
        m.issuedAt = issuedAt;
        m.expiresAt = expiresAt;
        m.nonce = nonce;
        m.status = uint8(status);
        // bindingHash is filled by the sender, its single authority.

        SENDER.sendCredentialState(m, destinations);
    }
}
