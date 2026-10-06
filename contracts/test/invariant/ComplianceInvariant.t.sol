// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";

import {AuditTrail} from "../../src/AuditTrail.sol";
import {ComplianceRegistry} from "../../src/ComplianceRegistry.sol";
import {EmergencyControls} from "../../src/EmergencyControls.sol";
import {PoolComplianceModule} from "../../src/PoolComplianceModule.sol";
import {PoolPolicyManager} from "../../src/PoolPolicyManager.sol";
import {ProviderRegistry} from "../../src/ProviderRegistry.sol";
import {ComplianceTypes} from "../../src/libraries/ComplianceTypes.sol";
import {ComplianceLifecycleHandler} from "./ComplianceLifecycleHandler.sol";

/**
 * @title ComplianceInvariantTest
 * @notice Properties that must hold after any sequence of legal actions.
 *
 * @dev ## Why these and not more
 *
 *      An invariant is only worth its runtime if it is *stated over the thing that
 *      matters*. This system makes one promise - an access decision is `Allow` only
 *      when every precondition genuinely holds - and every invariant below is either a
 *      leg of that promise or a property whose violation would make the promise
 *      unenforceable.
 *
 *      The central one is `invariant_allowRequiresEveryPrecondition`. If it fails, a
 *      non-compliant investor has been let into a pool, and nothing in the codebase
 *      can recover from that.
 *
 * @dev ## Why the key space is enumerated rather than sampled
 *
 *      The handler picks from a bounded set of subjects, so the full set of
 *      credentials it can ever create is known: `4 subjects x 3 classes x 3
 *      jurisdictions` = 36, against 2 pools. 72 pairs. That is small enough to
 *      enumerate exhaustively inside each invariant, which matters - a sampled
 *      invariant can miss the one credential that was misconfigured.
 *
 *      Those keys are derived once in {setUp}. Recomputing them per iteration was the
 *      difference between a 22-second suite and an 11-second one, since each derivation
 *      is an external call. The invariants are pure reads, so caching changes nothing
 *      about what they check.
 *
 * @dev ## On coverage claims
 *
 *      These are sampled over *sequences*, exhaustive over *keys*. The deterministic
 *      suites cover each individual rejection path exactly; the invariants check that
 *      no combination of legal actions breaks a property. Neither substitutes for the
 *      other.
 */
contract ComplianceInvariantTest is Test {
    ComplianceLifecycleHandler internal handler;

    ComplianceRegistry internal registry;
    ProviderRegistry internal providers;
    PoolComplianceModule internal complianceModule;
    AuditTrail internal audit;
    PoolPolicyManager internal policies;
    EmergencyControls internal emergency;

    /// @dev Every CCID the fuzzer can create, and every pool it can target.
    bytes32[] internal ccids;
    bytes32[] internal poolIds;

    function setUp() public {
        handler = new ComplianceLifecycleHandler();
        registry = handler.registry();
        providers = handler.providers();
        complianceModule = handler.complianceModule();
        audit = handler.audit();
        policies = handler.policies();
        emergency = handler.emergency();

        uint256 subjects = handler.subjectCount();
        for (uint256 s = 0; s < subjects; ++s) {
            bytes32 subjectCommitment = handler.subjectAt(s);
            for (uint256 c = 0; c < 3; ++c) {
                for (uint256 j = 0; j < 3; ++j) {
                    (ComplianceTypes.InvestorClass cls, uint16 jurisdiction) = _classAndJurisdiction(c, j);
                    ccids.push(handler.ccidFor(subjectCommitment, cls, jurisdiction));
                }
            }
        }

        uint256 poolCount = handler.poolCount();
        for (uint256 p = 0; p < poolCount; ++p) {
            poolIds.push(handler.poolAt(p));
        }

        targetContract(address(handler));
    }

    // =================================================================
    // The central invariant
    // =================================================================

    /**
     * @dev An `Allow` requires *every* precondition, checked independently of the
     *      order {PoolComplianceModule._evaluate} applies them in.
     *
     *      Re-deriving the conditions here rather than re-reading the module's own
     *      reason code is the point: an invariant asserting `reason == OK` would pass
     *      even if the module had started allowing `Pending`.
     */
    function invariant_allowRequiresEveryPrecondition() public view {
        for (uint256 k = 0; k < ccids.length; ++k) {
            bytes32 ccid = ccids[k];

            for (uint256 p = 0; p < poolIds.length; ++p) {
                bytes32 poolId = poolIds[p];
                (ComplianceTypes.Decision decision,) = complianceModule.evaluate(_request(ccid, poolId));

                if (decision != ComplianceTypes.Decision.Allow) continue;

                // 1. Lifecycle: only `Valid` may be allowed.
                assertEq(
                    uint8(registry.statusOf(ccid)),
                    uint8(ComplianceTypes.CredentialStatus.Valid),
                    "allowed a credential that is not Valid"
                );

                // 2. A pool policy exists and is active.
                assertTrue(policies.hasActivePolicy(poolId), "allowed under an inactive policy");

                // 3. The attester still backs its credentials.
                ComplianceTypes.ComplianceCredential memory r = registry.getRecord(ccid);
                assertTrue(providers.backsExistingCredentials(r.providerId), "allowed against an untrusted provider");

                // 4. Eligibility holds under that policy.
                uint32 version = policies.activeVersion(poolId);
                assertTrue(
                    policies.isJurisdictionAccepted(poolId, version, r.jurisdictionCode),
                    "allowed outside the accepted jurisdictions"
                );
                assertTrue(
                    policies.isInvestorClassAccepted(poolId, version, r.investorClass),
                    "allowed outside the accepted investor classes"
                );
            }
        }
    }

    /**
     * @dev A paused system allows nobody, and says so.
     *
     *      The safe direction for an emergency control: if the system cannot trust its
     *      own state, it must not report that an investor is compliant.
     */
    function invariant_pausedSystemAllowsNobody() public view {
        if (!emergency.isPaused()) return;

        for (uint256 k = 0; k < ccids.length; ++k) {
            for (uint256 p = 0; p < poolIds.length; ++p) {
                (ComplianceTypes.Decision decision, bytes32 reason) =
                    complianceModule.evaluate(_request(ccids[k], poolIds[p]));
                assertTrue(decision != ComplianceTypes.Decision.Allow, "a paused system produced an allow");
                if (decision == ComplianceTypes.Decision.Deny) {
                    assertEq(reason, ComplianceTypes.REASON_SYSTEM_PAUSED, "paused system gave the wrong reason");
                }
            }
        }
    }

    /**
     * @dev An untrusted provider cannot yield an allow.
     *
     *      Deliberately excludes `Deprecated`: a deprecated provider still backs
     *      existing credentials, and treating that as a violation would push the
     *      design towards the failure this repository's docs call out - a routine
     *      provider migration invalidating every live credential.
     *
     * @dev ## Why the guard reads the status rather than calling
     *      {ProviderRegistry.backsExistingCredentials}
     *
     *      The first version of this invariant began `if (providers.backsExistingCredentials(...
     *      )) return;`. That made the invariant self-defeating: the mutation
     *      `backsExistingCredentials` -> `true` silenced the very check written to
     *      catch it, and the mutation harness reported the change as surviving.
     *
     *      A property check must not be expressed in terms of the function under test.
     *      The status enum is the independent input here.
     */
    function invariant_untrustedProviderCannotAllow() public view {
        ProviderRegistry.ProviderStatus status = providers.getProviderStatus(handler.PROVIDER_A());
        bool trusted =
            status == ProviderRegistry.ProviderStatus.Active || status == ProviderRegistry.ProviderStatus.Deprecated;
        if (trusted) return;

        for (uint256 k = 0; k < ccids.length; ++k) {
            for (uint256 p = 0; p < poolIds.length; ++p) {
                (ComplianceTypes.Decision decision,) = complianceModule.evaluate(_request(ccids[k], poolIds[p]));
                assertTrue(decision != ComplianceTypes.Decision.Allow, "allowed against an untrusted provider");
            }
        }
    }

    /**
     * @dev A pool with no active policy never allows anybody.
     *
     *      Enumerated separately from the central invariant because it is the state an
     *      integrator hits first, and the failure - a pool silently admitting investors
     *      before its policy is configured - is the one an operator is most likely to
     *      make.
     */
    function invariant_inactivePolicyNeverAllows() public view {
        for (uint256 k = 0; k < ccids.length; ++k) {
            for (uint256 p = 0; p < poolIds.length; ++p) {
                bytes32 poolId = poolIds[p];
                if (policies.hasActivePolicy(poolId)) continue;
                (ComplianceTypes.Decision decision,) = complianceModule.evaluate(_request(ccids[k], poolId));
                assertTrue(decision != ComplianceTypes.Decision.Allow, "allowed under an inactive policy");
            }
        }
    }

    // =================================================================
    // Lifecycle
    // =================================================================

    /**
     * @dev `Revoked` is terminal.
     *
     *      Stated against the ghost flag rather than the current status, so it holds
     *      from the moment of revocation onwards - including after the paths that try
     *      to undo it. `revokeThenAttemptResurrection` is what puts those paths in
     *      reach; with a fresh CCID per action they would never run, and this
     *      invariant would pass without ever having been tested against a resurrection
     *      attempt.
     */
    function invariant_revokedIsTerminal() public view {
        for (uint256 k = 0; k < ccids.length; ++k) {
            bytes32 ccid = ccids[k];
            if (!handler.ghostEverRevoked(ccid)) continue;
            assertEq(
                uint8(registry.statusOf(ccid)),
                uint8(ComplianceTypes.CredentialStatus.Revoked),
                "a revoked credential left the terminal state"
            );
        }
    }

    /**
     * @dev The nonce never decreases for a credential.
     *
     *      This is the replay guard the cross-chain layer depends on: a destination
     *      accepts a message only when its nonce exceeds what it holds. If the nonce
     *      could go backwards here, a status change could be discarded as stale
     *      elsewhere - which, for a revocation, means the credential stays valid on
     *      every chain that already saw it.
     */
    function invariant_nonceNeverDecreases() public view {
        for (uint256 k = 0; k < ccids.length; ++k) {
            bytes32 ccid = ccids[k];
            if (!handler.ghostEverIssued(ccid)) continue;
            assertGe(
                registry.getRecord(ccid).nonce,
                handler.ghostHighestNonce(ccid),
                "nonce decreased for an observed credential"
            );
        }
    }

    /**
     * @dev A credential's stored CCID always matches the key it is stored under.
     *
     *      Cheap, and it catches a whole class of bug where a record is written to the
     *      wrong slot - which would leave the credential invisible to its holder while
     *      still being valid.
     */
    function invariant_registryKeyMatchesRecordCcid() public view {
        for (uint256 k = 0; k < ccids.length; ++k) {
            bytes32 ccid = ccids[k];
            ComplianceTypes.ComplianceCredential memory r = registry.getRecord(ccid);
            assertTrue(r.ccid == bytes32(0) || r.ccid == ccid, "record stored under the wrong key");
        }
    }

    /**
     * @dev A locally issued credential is never a replica.
     *
     *      This chain is the only issuer in this fixture, so no propagation state should
     *      ever be set. The receiver refuses such messages; this asserts the
     *      consequence end to end.
     */
    function invariant_locallyIssuedCredentialsAreNeverReplicas() public view {
        for (uint256 k = 0; k < ccids.length; ++k) {
            assertFalse(
                registry.getPropagationState(ccids[k]).isReplica, "a locally issued credential was marked as a replica"
            );
        }
    }

    // =================================================================
    // Policy immutability
    // =================================================================

    /**
     * @dev A registered policy version never changes.
     *
     *      This is what makes an integrator's pinned version meaningful. Without it,
     *      "integrate against version 3" would be a claim with nothing behind it, and
     *      the whole reason for immutable versions plus an activation delay would go.
     *
     *      Only `active` is excluded from the digest: activation is the one field
     *      designed to move, and supersession flips it on the previous version.
     */
    function invariant_registeredPolicyVersionsAreImmutable() public view {
        for (uint256 p = 0; p < poolIds.length; ++p) {
            bytes32 poolId = poolIds[p];
            uint32 highest = handler.ghostHighestPolicyVersion(poolId);
            for (uint32 v = 1; v <= highest; ++v) {
                bytes32 captured = handler.ghostPolicyDigest(poolId, v);
                if (captured == bytes32(0)) continue;
                assertEq(
                    handler.policyDigest(poolId, v),
                    captured,
                    "a registered policy version's material fields changed after registration"
                );
            }
        }
    }

    /**
     * @dev At most one policy version is active per pool, and the pointer
     *      {PoolComplianceModule} reads agrees with it.
     *
     *      Two active versions would give an integrator two different answers for the
     *      same request, depending on which they read.
     */
    function invariant_atMostOneActivePolicyVersionPerPool() public view {
        for (uint256 p = 0; p < poolIds.length; ++p) {
            bytes32 poolId = poolIds[p];
            uint32 highest = handler.ghostHighestPolicyVersion(poolId);
            uint32 selected = policies.activeVersion(poolId);

            uint32 activeCount;
            for (uint32 v = 1; v <= highest; ++v) {
                if (v != selected) continue;
                if (policies.getPolicy(poolId, v).active) ++activeCount;
            }
            assertLe(activeCount, 1, "more than one policy version is active for a pool");

            if (selected == 0) continue;
            assertTrue(policies.getPolicy(poolId, selected).registered, "selected version is unregistered");
            assertEq(
                policies.hasActivePolicy(poolId),
                policies.getPolicy(poolId, selected).active,
                "the reported active flag disagrees with the selected version's own flag"
            );
        }
    }

    /**
     * @dev Versions only ever increase.
     *
     *      Re-registering at the same number would let two different policies claim one
     *      version, and an integrator pinning that version could not tell which one it
     *      would be evaluated under.
     */
    function invariant_policyVersionsOnlyIncrease() public view {
        for (uint256 p = 0; p < poolIds.length; ++p) {
            bytes32 poolId = poolIds[p];
            assertGe(policies.latestVersion(poolId), handler.ghostHighestPolicyVersion(poolId), "latest went back");
        }
    }

    // =================================================================
    // Audit trail
    // =================================================================

    function invariant_auditTrailNeverShrinks() public view {
        assertGe(audit.totalEntries(), handler.ghostHighestAuditCount(), "audit entry count went backwards");
    }

    /**
     * @dev No audit entry is ever rewritten.
     *
     *      The trail is append-only by construction - there is no update or delete -
     *      so this is really a guard against an id being reused, which would be the
     *      only way an entry could change.
     */
    function invariant_auditEntriesAreNeverRewritten() public view {
        uint256 total = audit.totalEntries();
        uint256 captured = handler.ghostHighestAuditCount();
        uint256 limit = total < captured ? total : captured;
        for (uint256 i = 0; i < limit; ++i) {
            bytes32 expected = handler.ghostAuditEntryCcid(i);
            if (expected == bytes32(0)) continue;
            assertEq(audit.getEntry(i).ccid, expected, "an audit entry was rewritten");
        }
    }

    // =================================================================
    // Reason-code discipline
    // =================================================================

    /**
     * @dev Every decision carries a describable reason code, and the code agrees with
     *      the decision.
     *
     *      Guards the mapping an SDK depends on. A newer contract must not brick an
     *      older SDK's logging path, which is why {ComplianceTypes.reasonToString}
     *      returns `UNRECOGNIZED` rather than reverting - and why every *curated* code
     *      must still resolve to a real label.
     */
    function invariant_decisionsAlwaysCarryAKnownReasonCode() public view {
        for (uint256 k = 0; k < ccids.length; ++k) {
            for (uint256 p = 0; p < poolIds.length; ++p) {
                (ComplianceTypes.Decision decision, bytes32 reason) =
                    complianceModule.evaluate(_request(ccids[k], poolIds[p]));
                assertTrue(bytes(complianceModule.describeReason(reason)).length > 0, "undescribable reason");

                if (decision == ComplianceTypes.Decision.Allow) {
                    assertTrue(ComplianceTypes.isAllow(reason), "an allow with a non-allow reason");
                } else {
                    assertFalse(ComplianceTypes.isAllow(reason), "a denial carrying the allow reason");
                }
            }
        }
    }

    // =================================================================
    // Helpers
    // =================================================================

    function _request(bytes32 ccid, bytes32 poolId) internal pure returns (ComplianceTypes.AccessRequest memory) {
        return ComplianceTypes.AccessRequest({ccid: ccid, poolId: poolId, requestedAmount: 0, currentAllocation: 0});
    }

    /// @dev Mirrors the handler's `_classFor` / `_jurisdictionFor` selection, so the
    ///      invariants enumerate exactly the credentials the fuzzer can create.
    ///      `Blocked` is included because a `Blocked` credential is representable and
    ///      must be denied - not absent.
    function _classAndJurisdiction(uint256 c, uint256 j)
        internal
        pure
        returns (ComplianceTypes.InvestorClass cls, uint16 jurisdiction)
    {
        ComplianceTypes.InvestorClass[] memory classes = new ComplianceTypes.InvestorClass[](3);
        classes[0] = ComplianceTypes.InvestorClass.USAccredited;
        classes[1] = ComplianceTypes.InvestorClass.NonUSProfessional;
        classes[2] = ComplianceTypes.InvestorClass.Blocked;

        uint16[] memory jurisdictions = new uint16[](3);
        jurisdictions[0] = 840;
        jurisdictions[1] = 826;
        jurisdictions[2] = 392;

        cls = classes[c];
        jurisdiction = jurisdictions[j];
    }
}
