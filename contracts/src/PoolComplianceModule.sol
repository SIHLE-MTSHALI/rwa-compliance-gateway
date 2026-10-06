// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {AuditTrail} from "./AuditTrail.sol";
import {ComplianceRegistry} from "./ComplianceRegistry.sol";
import {EmergencyControls} from "./EmergencyControls.sol";
import {PoolPolicyManager} from "./PoolPolicyManager.sol";
import {ProviderRegistry} from "./ProviderRegistry.sol";
import {ComplianceTypes} from "./libraries/ComplianceTypes.sol";

/**
 * @title PoolComplianceModule
 * @notice The access check an RWA pool calls. Returns allow, deny, or
 *         review-required, always with a reason code.
 *
 * @dev ## Why this contract exists
 *
 *      A pool that calls `registry.isValid(ccid)` is reading one of several
 *      necessary conditions and treating it as sufficient. That call is `true` for a
 *      credential whose provider has since been paused, for one whose jurisdiction
 *      the pool does not accept, and for a replica this chain last heard from
 *      weeks ago.
 *
 *      This module is the single place all of those are considered together, so an
 *      integrator cannot accidentally implement a partial version of the rule.
 *
 * @dev ## Reason-code precedence
 *
 *      First failure wins, in this order:
 *
 *      1.  `SYSTEM_PAUSED`            - nothing can be trusted while paused.
 *      2.  `POOL_NOT_REGISTERED`      - no pool policy at all.
 *      3.  `POLICY_INACTIVE`          - policy exists but is not active.
 *      4.  `NO_CREDENTIAL`            - nothing presented.
 *      5.  `PENDING`                  - verification unfinished.
 *      6.  `REVOKED`                  - deliberate withdrawal.
 *      7.  `SUSPENDED`                - temporary issuer block.
 *      8.  `EXPIRED`                  - lapsed.
 *      9.  `PROVIDER_PAUSED`          - attester no longer trusted.
 *      10. `JURISDICTION_BLOCKED`     - pool does not serve this jurisdiction.
 *      11. `INVESTOR_CLASS_BLOCKED`   - pool does not serve this class.
 *      12. `STALE_DESTINATION`        - replica older than the pool tolerates.
 *      13. `ALLOCATION_CAP_EXCEEDED`  - total above the per-investor cap.
 *      14. `MANUAL_REVIEW_REQUIRED`   - policy demands human review.
 *      15. `OK`
 *
 *      Three orderings are deliberate:
 *
 *      - **`REVOKED` before `EXPIRED`** - revocation is the stronger, more
 *        deliberate signal, so it is reported even when the credential has also
 *        lapsed.
 *      - **`STALE_DESTINATION` after eligibility, before allocation** - the most
 *        useful thing to tell a holder is "we cannot currently confirm your
 *        eligibility" rather than "you are over your cap", which they may dispute.
 *      - **`MANUAL_REVIEW_REQUIRED` last** - a review requirement is a routing
 *        instruction, not a defect, so it should never mask a real denial.
 */
contract PoolComplianceModule {
    using ComplianceTypes for bytes32;

    ComplianceRegistry public immutable REGISTRY;
    ProviderRegistry public immutable PROVIDERS;
    PoolPolicyManager public immutable POLICIES;
    EmergencyControls public immutable EMERGENCY;
    AuditTrail public immutable AUDIT;

    /// @notice Emitted on allow, and on review-required.
    /// @dev Denials are not emitted by default: an emitted denial would let anyone
    ///      inflate a holder's public denial history by probing repeatedly, and the
    ///      view function already returns the reason to the caller. The `audit`
    ///      module records denials through an explicit, permissioned path.
    event AccessAllowed(
        bytes32 indexed ccid, bytes32 indexed poolId, address indexed caller, bytes32 reason, uint256 requestedAmount
    );
    event AccessReviewRequired(bytes32 indexed ccid, bytes32 indexed poolId, address indexed caller, bytes32 reason);

    error AuditNotConfigured();

    constructor(
        ComplianceRegistry registry,
        ProviderRegistry providers,
        PoolPolicyManager policies,
        EmergencyControls emergency,
        AuditTrail audit
    ) {
        REGISTRY = registry;
        PROVIDERS = providers;
        POLICIES = policies;
        EMERGENCY = emergency;
        AUDIT = audit;
    }

    /**
     * @notice Evaluate an access request. Pure and view.
     * @dev An integrator may `eth_call` this to preview a decision without any
     *      state change or event, which is what makes a preview UI possible.
     * @param request The credential, pool, and amounts.
     * @return decision Allow, Deny, or ReviewRequired.
     * @return reasonCode A `ComplianceTypes` reason code.
     */
    function evaluate(ComplianceTypes.AccessRequest calldata request)
        external
        view
        returns (ComplianceTypes.Decision decision, bytes32 reasonCode)
    {
        ComplianceTypes.AccessRequest memory req = request;
        return _evaluate(req);
    }

    /// @dev The single implementation of the decision. Every public entry point
    ///      funnels through here, so the documented precedence order is the only
    ///      order that can ever run.
    function _evaluate(ComplianceTypes.AccessRequest memory request)
        private
        view
        returns (ComplianceTypes.Decision decision, bytes32 reasonCode)
    {
        // A paused system cannot produce a trustworthy decision. Failing closed here
        // is the safe direction: during an incident, the answer is "no".
        if (EMERGENCY.isPaused()) return (ComplianceTypes.Decision.Deny, ComplianceTypes.REASON_SYSTEM_PAUSED);

        // --- Pool policy gates come first: no pool, no decision. ---
        //
        // Two distinct codes, because the two states demand different responses from
        // an integrator. "No policy has ever been registered" is an integration bug
        // on their side. "A policy exists but is switched off" is a deliberate
        // operational state - a `requiresManualReview` rollout, or an incident - and
        // will resolve on its own. Reporting both as "unregistered" would make a
        // pool operator's decision look like a broken integration.
        if (!POLICIES.hasAnyPolicy(request.poolId)) {
            return (ComplianceTypes.Decision.Deny, ComplianceTypes.REASON_POOL_NOT_REGISTERED);
        }
        if (!POLICIES.hasActivePolicy(request.poolId)) {
            return (ComplianceTypes.Decision.Deny, ComplianceTypes.REASON_POLICY_INACTIVE);
        }
        uint32 version = POLICIES.activeVersion(request.poolId);
        ComplianceTypes.PoolPolicy memory policy = POLICIES.getPolicy(request.poolId, version);
        if (!policy.registered || !policy.active) {
            return (ComplianceTypes.Decision.Deny, ComplianceTypes.REASON_POLICY_INACTIVE);
        }

        // --- Credential lifecycle. ---
        ComplianceTypes.CredentialStatus status = REGISTRY.statusOf(request.ccid);
        bytes32 lifecycleReason = _statusReason(status);
        if (lifecycleReason != ComplianceTypes.REASON_OK) {
            return (ComplianceTypes.Decision.Deny, lifecycleReason);
        }

        ComplianceTypes.ComplianceCredential memory r = REGISTRY.getRecord(request.ccid);

        // --- Provider must still back its attestations. ---
        if (!PROVIDERS.backsExistingCredentials(r.providerId)) {
            return (ComplianceTypes.Decision.Deny, ComplianceTypes.REASON_PROVIDER_PAUSED);
        }

        // --- Eligibility under this pool's policy. ---
        if (!POLICIES.isJurisdictionAccepted(request.poolId, version, r.jurisdictionCode)) {
            return (ComplianceTypes.Decision.Deny, ComplianceTypes.REASON_JURISDICTION_BLOCKED);
        }
        if (!POLICIES.isInvestorClassAccepted(request.poolId, version, r.investorClass)) {
            return (ComplianceTypes.Decision.Deny, ComplianceTypes.REASON_INVESTOR_CLASS_BLOCKED);
        }

        // --- Destination freshness, replicas only. ---
        if (policy.requiresFreshReplica && REGISTRY.getPropagationState(request.ccid).isReplica) {
            uint64 tolerance = policy.maxReplicaAge == 0 ? 1 days : policy.maxReplicaAge;
            if (REGISTRY.ageOf(request.ccid) > tolerance) {
                return (ComplianceTypes.Decision.Deny, ComplianceTypes.REASON_STALE_DESTINATION);
            }
        }

        // --- Allocation cap, evaluated against the total. ---
        //
        // The cap is checked against `currentAllocation + requestedAmount`, not the
        // increment alone. Checking only the increment would let a holder who
        // already sits at the cap add another full cap's worth.
        if (request.requestedAmount != 0) {
            uint256 total = request.currentAllocation + request.requestedAmount;
            if (POLICIES.exceedsAllocationCap(request.poolId, version, total)) {
                return (ComplianceTypes.Decision.Deny, ComplianceTypes.REASON_ALLOCATION_CAP_EXCEEDED);
            }
        }

        // --- Review requirement is a routing instruction, so it comes last. ---
        if (policy.requiresManualReview) {
            return (ComplianceTypes.Decision.ReviewRequired, ComplianceTypes.REASON_MANUAL_REVIEW_REQUIRED);
        }

        return (ComplianceTypes.Decision.Allow, ComplianceTypes.REASON_OK);
    }

    /**
     * @notice Evaluate and emit an audit event for allows and reviews.
     * @dev The non-view entry point for integrators that want an on-chain trail.
     *      Denials still emit nothing here; see {AccessAllowed}.
     */
    function evaluateAndRecord(ComplianceTypes.AccessRequest calldata request)
        external
        returns (ComplianceTypes.Decision decision, bytes32 reasonCode)
    {
        // Copy from calldata into memory so the decision logic has exactly one
        // implementation, shared by the view and state-changing entry points. The
        // precedence order cannot then drift between them.
        ComplianceTypes.AccessRequest memory req = request;
        (decision, reasonCode) = _evaluate(req);

        if (decision == ComplianceTypes.Decision.Allow) {
            emit AccessAllowed(request.ccid, request.poolId, msg.sender, reasonCode, request.requestedAmount);
            if (address(AUDIT) != address(0)) {
                AUDIT.recordDecision(
                    request.ccid, request.poolId, msg.sender, decision, reasonCode, request.requestedAmount
                );
            }
        } else if (decision == ComplianceTypes.Decision.ReviewRequired) {
            emit AccessReviewRequired(request.ccid, request.poolId, msg.sender, reasonCode);
            if (address(AUDIT) != address(0)) {
                AUDIT.recordDecision(
                    request.ccid, request.poolId, msg.sender, decision, reasonCode, request.requestedAmount
                );
            }
        }
    }

    /**
     * @notice Convenience: does this credential pass the lifecycle and provider checks?
     * @dev Explicitly **not** an access gate. It answers "is the credential itself
     *      in good standing", which is what a holder-facing status view needs, and
     *      deliberately ignores pool policy, allocation, and review requirements -
     *      because those are properties of the *request*, not of the credential.
     *
     *      Written as a direct check rather than by reinterpreting {evaluate}'s
     *      output: inferring credential health from a pool-specific decision means
     *      a holder on a pool with no active policy looks credential-ineligible,
     *      which is both wrong and alarming.
     */
    function isCredentialEligible(bytes32 ccid) external view returns (bool) {
        if (REGISTRY.statusOf(ccid) != ComplianceTypes.CredentialStatus.Valid) return false;
        ComplianceTypes.ComplianceCredential memory r = REGISTRY.getRecord(ccid);
        return PROVIDERS.backsExistingCredentials(r.providerId);
    }

    /// @notice Human-readable reason code, for events, CLI, and SDK display.
    function describeReason(bytes32 reasonCode) external pure returns (string memory) {
        return ComplianceTypes.reasonToString(reasonCode);
    }

    /// @notice Human-readable credential status.
    function describeStatus(ComplianceTypes.CredentialStatus status) external pure returns (string memory) {
        return ComplianceTypes.statusToString(status);
    }

    /// @notice Human-readable investor class.
    function describeInvestorClass(ComplianceTypes.InvestorClass cls) external pure returns (string memory) {
        return ComplianceTypes.investorClassToString(cls);
    }

    // ---------------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------------

    /**
     * @dev Maps a non-`Valid` status to its reason, in precedence order.
     */
    function _statusReason(ComplianceTypes.CredentialStatus status) private pure returns (bytes32 reasonCode) {
        if (status == ComplianceTypes.CredentialStatus.Valid) return ComplianceTypes.REASON_OK;
        if (status == ComplianceTypes.CredentialStatus.Unknown) return ComplianceTypes.REASON_NO_CREDENTIAL;
        if (status == ComplianceTypes.CredentialStatus.Pending) return ComplianceTypes.REASON_PENDING;
        if (status == ComplianceTypes.CredentialStatus.Revoked) return ComplianceTypes.REASON_REVOKED;
        if (status == ComplianceTypes.CredentialStatus.Suspended) return ComplianceTypes.REASON_SUSPENDED;
        return ComplianceTypes.REASON_EXPIRED;
    }
}
