// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ComplianceTypes} from "./libraries/ComplianceTypes.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title PoolPolicyManager
 * @notice Versioned, issuer-configured access policy for each RWA pool.
 *
 * @dev ## Versioning and the delay
 *
 *      Policies are immutable once registered. A change means a new version, and
 *      {activatePolicyVersion} can only take effect after {POLICY_ACTIVATION_DELAY}.
 *
 *      That delay is the whole reason versioning is worth doing. Without it, an
 * * issuer - or someone who has compromised an issuer key - could tighten a policy
 *      so sharply that every existing investor is instantly ineligible, with no
 *      window in which anyone could notice or respond. Policy that can change
 *      without notice is indistinguishable from arbitrary denial.
 *
 *      Because each version is immutable, an integrator can pin the version it
 *      integrated against and know exactly what it will be evaluated under.
 *
 * @dev ## `maxAllocationPerInvestor == 0` means uncapped
 *
 *      Zero is the natural "no limit configured" value and is indistinguishable
 *      from a cap of zero. Rather than treat zero as a cap that rejects
 *      everything, it means uncapped - and pools that want a cap must set one.
 */
contract PoolPolicyManager is AccessControl {
    using ComplianceTypes for bytes32;

    /// @dev May register, activate, and supersede policies.
    bytes32 public constant ISSUER_ADMIN = keccak256("ISSUER_ADMIN");

    /// @dev Seconds a pending version must wait before it can be activated.
    uint64 public constant POLICY_ACTIVATION_DELAY = 7 days;

    /// @dev Max jurisdictions in one policy; bounds loop cost.
    uint256 public constant MAX_JURISDICTIONS = 64;

    /// @dev Max investor classes per policy. There are only 4 enum values, so this
    ///      is a sanity bound rather than a gas bound.
    uint256 public constant MAX_CLASSES = 4;

    event PolicyRegistered(
        bytes32 indexed poolId,
        uint32 indexed version,
        bool requiresManualReview,
        uint256 maxAllocationPerInvestor,
        uint64 activateAfter
    );
    event PolicyActivated(bytes32 indexed poolId, uint32 indexed version);
    event PolicyDeactivated(bytes32 indexed poolId, uint32 indexed version);
    event PolicyPending(bytes32 indexed poolId, uint32 indexed version, uint64 activateAfter);

    /// @dev poolId => version => policy
    mapping(bytes32 => mapping(uint32 => ComplianceTypes.PoolPolicy)) private _policies;

    /// @dev poolId => currently active version, 0 when none.
    mapping(bytes32 => uint32) public activeVersion;

    /// @dev poolId => highest version registered.
    mapping(bytes32 => uint32) public latestVersion;

    error NotIssuerAdmin(address caller);
    error PoolNotRegistered(bytes32 poolId);
    /// @dev Distinct from {PoolNotRegistered} so a bad constructor argument is not
    ///      reported as an unknown pool.
    error InvalidAdminAddress();
    error VersionAlreadyRegistered(bytes32 poolId, uint32 version);
    error VersionMustIncrease(bytes32 poolId, uint32 registered, uint32 attempted);
    error TooManyJurisdictions(uint256 length);
    error TooManyClasses(uint256 length);
    error ActivationDelayNotElapsed(uint64 activateAfter, uint64 nowTs);
    error NoVersionRegistered(bytes32 poolId);

    constructor(address admin) {
        if (admin == address(0)) revert InvalidAdminAddress();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ISSUER_ADMIN, admin);

        // `AccessControl.grantRole` resolves a role's admin to `bytes32(0)` unless
        // told otherwise, and then no account can satisfy it. Without this the
        // `ISSUER_ADMIN` role would be permanently ungrantable, so an issuer key
        // could never be handed over or rotated after deployment.
        _setRoleAdmin(ISSUER_ADMIN, DEFAULT_ADMIN_ROLE);
    }

    modifier onlyIssuerAdmin() {
        if (!hasRole(ISSUER_ADMIN, msg.sender)) revert NotIssuerAdmin(msg.sender);
        _;
    }

    /**
     * @notice Register a new immutable policy version.
     * @dev Not yet active. Call {activatePolicyVersion} once the delay elapses.
     * @param acceptedJurisdictions Allowed ISO 3166-1 numeric codes. Empty means
     *        all jurisdictions are permitted.
     * @param acceptedInvestorClasses Allowed classes. Empty means all except
     *        `Blocked`, which is never implicitly accepted - an issuer must opt in
     *        to serving blocked investors explicitly.
     */
    function registerPolicy(
        bytes32 poolId,
        bool requiresManualReview,
        uint16[] calldata acceptedJurisdictions,
        ComplianceTypes.InvestorClass[] calldata acceptedInvestorClasses,
        bool requiresFreshReplica,
        uint64 maxReplicaAge,
        uint256 maxAllocationPerInvestor,
        ComplianceTypes.RevocationMode revocationMode,
        uint64 effectiveAt
    ) external onlyIssuerAdmin {
        if (poolId == bytes32(0)) revert PoolNotRegistered(poolId);
        if (acceptedJurisdictions.length > MAX_JURISDICTIONS) {
            revert TooManyJurisdictions(acceptedJurisdictions.length);
        }
        if (acceptedInvestorClasses.length > MAX_CLASSES) revert TooManyClasses(acceptedInvestorClasses.length);

        uint32 version = latestVersion[poolId] + 1;
        if (version == 0) revert VersionMustIncrease(poolId, latestVersion[poolId], version);

        ComplianceTypes.PoolPolicy storage p = _policies[poolId][version];
        p.poolId = poolId;
        p.version = version;
        p.active = false;
        p.registered = true;
        p.requiresManualReview = requiresManualReview;
        p.requiresFreshReplica = requiresFreshReplica;
        p.maxReplicaAge = maxReplicaAge;
        p.maxAllocationPerInvestor = maxAllocationPerInvestor;
        p.revocationMode = revocationMode;
        p.effectiveAt = effectiveAt;
        p.createdAt = uint64(block.timestamp);
        for (uint256 i = 0; i < acceptedJurisdictions.length; ++i) {
            p.acceptedJurisdictions.push(acceptedJurisdictions[i]);
        }
        for (uint256 i = 0; i < acceptedInvestorClasses.length; ++i) {
            p.acceptedInvestorClasses.push(acceptedInvestorClasses[i]);
        }

        latestVersion[poolId] = version;
        emit PolicyRegistered(poolId, version, requiresManualReview, maxAllocationPerInvestor, 0);
    }

    /**
     * @notice Activate a registered version, once its delay has elapsed.
     * @dev Deactivates the previously active version, so exactly one is active per
     *      pool at a time. A pool with two active versions would give integrators
     *      an ambiguous answer for the same request.
     */
    function activatePolicyVersion(bytes32 poolId, uint32 version) external onlyIssuerAdmin {
        ComplianceTypes.PoolPolicy storage p = _policies[poolId][version];
        if (!p.registered) revert PoolNotRegistered(poolId);

        uint64 activateAfter = p.createdAt + POLICY_ACTIVATION_DELAY;
        if (uint64(block.timestamp) < activateAfter) {
            revert ActivationDelayNotElapsed(activateAfter, uint64(block.timestamp));
        }

        uint32 previous = activeVersion[poolId];
        if (previous != 0 && previous != version) {
            _policies[poolId][previous].active = false;
            emit PolicyDeactivated(poolId, previous);
        }

        p.active = true;
        activeVersion[poolId] = version;
        emit PolicyActivated(poolId, version);
    }

    /// @notice Deactivate the active version without replacing it.
    /// @dev Closes a pool to new access while leaving the policy readable, so an
    ///      integrator can still explain a past decision.
    function deactivateActivePolicy(bytes32 poolId) external onlyIssuerAdmin {
        uint32 version = activeVersion[poolId];
        if (version == 0) revert NoVersionRegistered(poolId);
        _policies[poolId][version].active = false;
        emit PolicyDeactivated(poolId, version);
    }

    /// @dev Notifies observers that a version is registered and pending activation.
    function notifyPending(bytes32 poolId, uint32 version) external onlyIssuerAdmin {
        ComplianceTypes.PoolPolicy storage p = _policies[poolId][version];
        if (!p.registered) revert PoolNotRegistered(poolId);
        emit PolicyPending(poolId, version, p.createdAt + POLICY_ACTIVATION_DELAY);
    }

    // ---------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------

    function getPolicy(bytes32 poolId, uint32 version) external view returns (ComplianceTypes.PoolPolicy memory) {
        return _policies[poolId][version];
    }

    /// @notice The currently active policy, or a zeroed struct when none is.
    function getActivePolicy(bytes32 poolId) external view returns (ComplianceTypes.PoolPolicy memory) {
        uint32 version = activeVersion[poolId];
        if (version == 0) return _policies[poolId][0];
        return _policies[poolId][version];
    }

    /**
     * @notice True when the pool has an active, effective policy.
     * @dev Folds together "a version is selected" and "that version is active", so
     *      an integrator cannot pass a check while the policy behind it is off.
     */
    function hasActivePolicy(bytes32 poolId) external view returns (bool) {
        uint32 version = activeVersion[poolId];
        if (version == 0) return false;
        ComplianceTypes.PoolPolicy storage p = _policies[poolId][version];
        return p.registered && p.active;
    }

    /**
     * @notice True when any policy version has ever been registered for the pool.
     * @dev The counterpart to {hasActivePolicy}, and the reason
     *      `REASON_POOL_NOT_REGISTERED` and `REASON_POLICY_INACTIVE` are two codes
     *      rather than one.
     *
     *      They demand different responses from an integrator: "never configured" is
     *      an integration bug on their side, while "configured but switched off" is a
     *      deliberate operational state that will resolve on its own. Collapsing them
     *      would make the first indistinguishable from the second, so a pool
     *      operator deactivating a policy would look like a broken integration.
     */
    function hasAnyPolicy(bytes32 poolId) external view returns (bool) {
        return latestVersion[poolId] != 0;
    }

    /**
     * @notice True when the pool has a selected version that is currently off.
     * @dev Convenience for integrators that want to distinguish "switched off" from
     *      "never configured" without reading two separate fields.
     */
    function isPolicyDeactivated(bytes32 poolId) external view returns (bool) {
        // Reads the state directly rather than delegating to {hasAnyPolicy} and
        // {hasActivePolicy}: Solidity does not allow an `external` function to call
        // another one internally, and the duplication is three lines.
        uint32 latest = latestVersion[poolId];
        if (latest == 0) return false;
        uint32 version = activeVersion[poolId];
        if (version == 0) return true; // registered but nothing selected yet
        ComplianceTypes.PoolPolicy storage p = _policies[poolId][version];
        return !(p.registered && p.active);
    }

    function isJurisdictionAccepted(bytes32 poolId, uint32 version, uint16 jurisdictionCode)
        external
        view
        returns (bool)
    {
        ComplianceTypes.PoolPolicy storage p = _policies[poolId][version];
        if (p.acceptedJurisdictions.length == 0) return true; // empty means all
        for (uint256 i = 0; i < p.acceptedJurisdictions.length; ++i) {
            if (p.acceptedJurisdictions[i] == jurisdictionCode) return true;
        }
        return false;
    }

    function isInvestorClassAccepted(bytes32 poolId, uint32 version, ComplianceTypes.InvestorClass cls)
        external
        view
        returns (bool)
    {
        ComplianceTypes.PoolPolicy storage p = _policies[poolId][version];
        if (p.acceptedInvestorClasses.length == 0) {
            // An empty list never implicitly accepts `Blocked`. An issuer must opt
            // in to serving blocked investors explicitly.
            return cls != ComplianceTypes.InvestorClass.Blocked;
        }
        for (uint256 i = 0; i < p.acceptedInvestorClasses.length; ++i) {
            if (p.acceptedInvestorClasses[i] == cls) return true;
        }
        return false;
    }

    /// @notice Whether a total allocation would exceed the policy cap. Zero means uncapped.
    function exceedsAllocationCap(bytes32 poolId, uint32 version, uint256 totalRequested) external view returns (bool) {
        ComplianceTypes.PoolPolicy storage p = _policies[poolId][version];
        if (p.maxAllocationPerInvestor == 0) return false;
        return totalRequested > p.maxAllocationPerInvestor;
    }
}
