// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console} from "forge-std/Test.sol";

import {ProviderRegistry} from "../../src/ProviderRegistry.sol";
import {ComplianceTypes} from "../../src/libraries/ComplianceTypes.sol";
import {ComplianceLifecycleHandler} from "./ComplianceLifecycleHandler.sol";

/**
 * @title HandlerCoverageTest
 * @notice Proves the invariant suite's handler actually reaches the states the
 *         invariants are stated over.
 *
 * @dev ## Why this exists
 *
 *      An invariant suite can pass while testing nothing. The failure mode is
 *      specific and it bit this repository: the handler's actions eventually drive the
 *      system into a state where *every* action reverts - `EmergencyControls.pause`
 *      with no automatic way back, and `ProviderRegistry` status `Revoked`, both of
 *      which gate every gateway write. From that point on no credential is issued, no
 *      nonce advances, no policy is registered, and every ghost variable stays at
 *      zero. The invariants still "pass", because they are all conditioned on ghost
 *      state that never becomes true.
 *
 *      Measured on the first version of the handler: **1 of 36** credentials ever
 *      issued. A six-mutation check reported every mutation as surviving, and the
 *      correct conclusion was not "the mutations are harmless" but "the suite was
 *      blind".
 *
 *      So coverage of the handler is itself a tested property. These thresholds are
 *      deliberately below what a healthy run achieves - the point is to fail loudly
 *      when a handler change collapses the reachable state space, not to pin an exact
 *      number that would churn on every Foundry release.
 *
 * @dev ## What is asserted, and why each one matters
 *
 *      | Assertion | Invariant it protects from going vacuous |
 *      |-----------|--------------------------------------------|
 *      | most keys issued | `allowRequiresEveryPrecondition`, `revokedIsTerminal` |
 *      | some keys revoked | `revokedIsTerminal` |
 *      | nonces advance | `nonceNeverDecreases` |
 *      | policy digests captured | `registeredPolicyVersionsAreImmutable` |
 *      | pool policy state varies | `inactivePolicyNeverAllows` |
 *      | audit entries recorded | `auditTrailNeverShrinks` |
 *      | stale-nonce renewals are attempted | `nonceNeverDecreases` |
 */
contract HandlerCoverageTest is Test {
    ComplianceLifecycleHandler internal handler;

    bytes32[] internal ccids;
    bytes32[] internal poolIds;

    /// @dev Seeds per pass. Roughly 360 handler calls, in the same shape the fuzzer
    ///      produces, so a healthy run clears every threshold comfortably.
    uint256 internal constant PASSES = 40;

    function setUp() public {
        handler = new ComplianceLifecycleHandler();

        ComplianceTypes.InvestorClass[] memory classes = new ComplianceTypes.InvestorClass[](3);
        classes[0] = ComplianceTypes.InvestorClass.USAccredited;
        classes[1] = ComplianceTypes.InvestorClass.NonUSProfessional;
        classes[2] = ComplianceTypes.InvestorClass.Blocked;
        uint16[] memory jurisdictions = new uint16[](3);
        jurisdictions[0] = 840;
        jurisdictions[1] = 826;
        jurisdictions[2] = 392;

        uint256 subjects = handler.subjectCount();
        for (uint256 s = 0; s < subjects; ++s) {
            for (uint256 c = 0; c < 3; ++c) {
                for (uint256 j = 0; j < 3; ++j) {
                    ccids.push(handler.ccidFor(handler.subjectAt(s), classes[c], jurisdictions[j]));
                }
            }
        }
        uint256 poolCount = handler.poolCount();
        for (uint256 p = 0; p < poolCount; ++p) {
            poolIds.push(handler.poolAt(p));
        }
    }

    // -----------------------------------------------------------------
    // The drive
    // -----------------------------------------------------------------

    function test_HandlerReachesTheStatesTheInvariantsDependOn() public {
        uint256 issued;
        uint256 revoked;
        uint256 nonceAdvanced;
        uint256 digests;
        uint256 policiesInactiveSeen;
        uint256 policiesActiveSeen;

        uint256[18] memory actionOk;
        uint256[18] memory actionRevert;

        for (uint256 s = 0; s < PASSES; ++s) {
            // Ordered so the recovery and lifecycle actions get a window on a `Valid`
            // credential *before* revocation takes it away.
            //
            // The first ordering ran revoke first, so by the time `renewCredential` and
            // `renewWithStaleNonce` were reached every credential was already terminal
            // and both reverted on `IllegalTransition` - the registry's revoked-guard,
            // which runs before the nonce guard. Mutation M3 ("renewal accepts a
            // non-increasing nonce") therefore went untested.
            for (uint256 w = 0; w < 18; ++w) {
                uint256 slot;
                if (w == 0) slot = 0; // issue
                else if (w == 1) slot = 4; // renew
                else if (w == 2) slot = 6; // stale-nonce renewal
                else if (w == 3) slot = 5; // beginVerification
                else if (w == 4) slot = 2; // suspend
                else if (w == 5) slot = 3; // resume
                else if (w == 6) slot = 1; // revoke
                else if (w == 7) slot = 7; // revoke-then-resurrect
                else if (w == 8) slot = 8; // expiry sweep
                else if (w == 9) slot = 9; // provider status
                else if (w == 10) slot = 10; // register policy
                else if (w == 11) slot = 11; // activate policy
                else if (w == 12) slot = 12; // deactivate policy
                else if (w == 13) slot = 13; // evaluate
                else if (w == 14) slot = 14; // pause
                else if (w == 15) slot = 15; // unpause
                else if (w == 16) slot = 16; // cancel unpause
                else slot = 17; // reconcile

                bool ok = _attempt(s, slot);
                if (ok) ++actionOk[slot];
                else ++actionRevert[slot];
            }
        }

        for (uint256 k = 0; k < ccids.length; ++k) {
            bytes32 ccid = ccids[k];
            if (handler.ghostEverIssued(ccid)) ++issued;
            if (handler.ghostEverRevoked(ccid)) ++revoked;
            if (handler.ghostHighestNonce(ccid) > 0) ++nonceAdvanced;
        }

        for (uint256 p = 0; p < poolIds.length; ++p) {
            bytes32 poolId = poolIds[p];
            uint32 highest = handler.ghostHighestPolicyVersion(poolId);
            for (uint32 v = 1; v <= highest; ++v) {
                if (handler.ghostPolicyDigest(poolId, v) != bytes32(0)) ++digests;
            }
            if (handler.policies().hasActivePolicy(poolId)) ++policiesActiveSeen;
            else ++policiesInactiveSeen;
        }

        console.log("keys issued        ", issued, "/", ccids.length);
        console.log("keys revoked       ", revoked);
        console.log("keys w/ nonce      ", nonceAdvanced);
        console.log("policy digests     ", digests);
        console.log("audit entries      ", handler.audit().totalEntries());
        console.log("policy active/inact", policiesActiveSeen, "/", policiesInactiveSeen);

        string[18] memory names = [
            "issue",
            "revoke",
            "suspend",
            "resume",
            "renew",
            "beginVerif",
            "staleRenew",
            "revokeThen",
            "sweep",
            "provStatus",
            "regPolicy",
            "actPolicy",
            "deactPolicy",
            "evaluate",
            "pause",
            "unpause",
            "cancelUnpause",
            "reconcile"
        ];
        for (uint256 i = 0; i < names.length; ++i) {
            console.log("  ok", i, actionOk[i]);
            console.log("  rv", i, actionRevert[i]);
        }

        // --- Thresholds -----------------------------------------------------------------
        //
        // Roughly half the keys. The first version of this handler reached 1 of 36,
        // which cleared none of these.

        assertGe(issued, ccids.length / 2, "handler issues too few credentials: lifecycle invariants are vacuous");
        assertGe(revoked, 1, "no credential was ever revoked: `revokedIsTerminal` is vacuous");
        assertGe(nonceAdvanced, ccids.length / 4, "nonces barely advance: `nonceNeverDecreases` is vacuous");
        assertGe(digests, 2, "no policy version digest was captured: version immutability is vacuous");
        assertGe(handler.audit().totalEntries(), 2, "no audit entries: the append-only invariants are vacuous");

        assertGt(policiesActiveSeen, 0, "no pool ever had an active policy");
        // Both policy states must appear, or `inactivePolicyNeverAllows` never sees the
        // state it is about.
        assertGt(policiesInactiveSeen, 0, "no pool was ever deactivated: policy-state coverage is one-sided");
    }

    // -----------------------------------------------------------------
    // Additional targeted coverage
    // -----------------------------------------------------------------

    /**
     * @dev The stale-nonce renewal path must actually be attempted, and must always
     *      revert.
     *
     *      This is the only place `invariant_nonceNeverDecreases` is tested against
     *      its own failure mode. If the registry's monotonicity guard were removed,
     *      this test would fail - and without it, the mutation check reported that
     *      guard as uncaught.
     */
    function test_StaleNonceRenewalIsAlwaysRejected() public {
        bytes32 subject = handler.subjectAt(0);
        bytes32 ccid = handler.ccidFor(subject, ComplianceTypes.InvestorClass.USAccredited, 840);

        _issue(ccid, subject);
        assertTrue(handler.ghostEverIssued(ccid), "fixture credential was not issued");

        uint64 before = handler.ghostHighestNonce(ccid);
        assertGt(before, 0, "the credential has a nonce to go stale");

        vm.expectRevert();
        handler.renewWithStaleNonceForTesting(ccid);

        assertEq(
            handler.ghostHighestNonce(ccid),
            before,
            "a stale-nonce renewal was accepted, or the attempt changed observable state"
        );
        assertEq(
            uint8(handler.registry().statusOf(ccid)),
            uint8(ComplianceTypes.CredentialStatus.Valid),
            "the credential's state is untouched by the refused attempt"
        );
    }

    /**
     * @dev Every route back to `Valid` from `Revoked` must be refused.
     *
     *      Stated directly rather than left to the fuzzer, because the compound action
     *      only reaches it when it happens to pick a credential that exists and is not
     *      already revoked.
     */
    function test_RevocationIsTerminalAgainstEveryRecoveryRoute() public {
        bytes32 subject = handler.subjectAt(1);
        bytes32 ccid = handler.ccidFor(subject, ComplianceTypes.InvestorClass.USAccredited, 840);

        _issue(ccid, subject);
        handler.revokeCredentialForTesting(ccid);
        assertEq(
            uint8(handler.registry().statusOf(ccid)),
            uint8(ComplianceTypes.CredentialStatus.Revoked),
            "fixture credential was not revoked"
        );

        // Route 1: resume.
        vm.expectRevert();
        handler.resumeCredentialForTesting(ccid);

        // Route 2: suspend.
        vm.expectRevert();
        handler.suspendCredentialForTesting(ccid);

        // Route 3: renewal with a fresh, higher nonce and a provider result that passes
        // every issuance check. This is the strongest route available - it is exactly
        // what a legitimate renewal looks like.
        //
        // The nonce is read into a local first. `handler.ghostHighestNonce(ccid)` in
        // the argument list is an external call, and it would consume the armed
        // expectation - leaving the renewal itself unasserted. See
        // CheatcodeSemanticsTest; this is the fourth time that footgun has cost time
        // in this repository.
        uint64 higherNonce = handler.ghostHighestNonce(ccid) + 100;
        vm.expectRevert();
        handler.renewCredentialForTesting(ccid, higherNonce);

        assertEq(uint8(handler.registry().statusOf(ccid)), uint8(ComplianceTypes.CredentialStatus.Revoked));
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    function registryStatus(bytes32 ccid) internal view returns (ComplianceTypes.CredentialStatus) {
        return handler.registry().statusOf(ccid);
    }

    function _issue(bytes32 ccid, bytes32 subject) internal {
        handler.issueCredentialForTesting(ccid, subject);
    }

    /**
     * @dev Dispatch one handler action, reporting whether it succeeded.
     * @dev A low-level call rather than `try/catch`: the handler is invoked by address,
     *      which is also how the fuzzer reaches it, so this reproduces the real path.
     */
    function _attempt(uint256 seed, uint256 which) internal returns (bool ok) {
        bytes memory data;
        if (which == 0) data = abi.encodeCall(handler.issueCredential, (seed));
        else if (which == 1) data = abi.encodeCall(handler.revokeCredential, (seed));
        else if (which == 2) data = abi.encodeCall(handler.suspendCredential, (seed));
        else if (which == 3) data = abi.encodeCall(handler.resumeCredential, (seed));
        else if (which == 4) data = abi.encodeCall(handler.renewCredential, (seed));
        else if (which == 5) data = abi.encodeCall(handler.beginVerification, (seed));
        else if (which == 6) data = abi.encodeCall(handler.renewWithStaleNonce, (seed));
        else if (which == 7) data = abi.encodeCall(handler.revokeThenAttemptResurrection, (seed));
        else if (which == 8) data = abi.encodeCall(handler.sweepExpiries, (seed));
        else if (which == 9) data = abi.encodeCall(handler.setProviderStatus, (seed));
        else if (which == 10) data = abi.encodeCall(handler.registerPolicyVersion, (seed));
        else if (which == 11) data = abi.encodeCall(handler.activatePolicyVersion, (seed));
        else if (which == 12) data = abi.encodeCall(handler.deactivatePolicy, (seed));
        else if (which == 13) data = abi.encodeCall(handler.evaluateAccess, (seed));
        else if (which == 14) data = abi.encodeCall(handler.pauseSystem, (seed));
        else if (which == 15) data = abi.encodeCall(handler.scheduleAndExecuteUnpause, (seed));
        else if (which == 16) data = abi.encodeCall(handler.cancelUnpause, ());
        else data = abi.encodeCall(handler.reconcileSystem, ());
        ok = _call(data, which);
    }

    /// @dev Returns whether the call succeeded; logs the action index and any revert
    ///      selector, so a coverage failure names which action is stuck.
    function _call(bytes memory data, uint256 which) internal returns (bool ok) {
        bytes memory ret;
        (ok, ret) = address(handler).call(data);
        if (!ok) {
            console.log("act", which);
            if (ret.length >= 4) console.logBytes4(bytes4(_firstFour(ret)));
        }
    }

    function _firstFour(bytes memory b) internal pure returns (bytes memory out) {
        out = new bytes(4);
        for (uint256 i = 0; i < 4; ++i) {
            out[i] = b[i];
        }
    }
}
