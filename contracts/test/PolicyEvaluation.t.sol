// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {AuditTrail} from "../src/AuditTrail.sol";
import {PoolComplianceModule} from "../src/PoolComplianceModule.sol";
import {ProviderRegistry} from "../src/ProviderRegistry.sol";
import {ComplianceTypes} from "../src/libraries/ComplianceTypes.sol";
import {ComplianceTestBase} from "./helpers/ComplianceTestBase.sol";

/**
 * @title PolicyEvaluationTest
 * @notice The access-decision suite.
 *
 * @dev ## Why this suite carries the most weight
 *
 *      Every other contract in this repository exists to make one boolean
 *      trustworthy. This is the contract that produces it, and its security
 *      argument is entirely the precedence order in
 *      {PoolComplianceModule._evaluate}.
 *
 *      So these tests are organised around that order rather than around the
 *      individual conditions: for each denial reason there is a test that
 *      establishes the condition, and a test that establishes it does *not*
 *      mask a reason that outranks it.
 */
contract PolicyEvaluationTest is ComplianceTestBase {
    bytes32 internal poolId = keccak256("pool.treasury");

    // -----------------------------------------------------------------
    // The one path that must allow
    // -----------------------------------------------------------------

    function test_AllowsFullyCompliantInvestor() public {
        _seedPermissivePolicy(poolId);
        bytes32 ccid = _issue(SUBJECT, 1);

        (ComplianceTypes.Decision decision, bytes32 reason) = sourceModule.evaluate(_request(ccid, poolId));

        assertEq(uint8(decision), uint8(ComplianceTypes.Decision.Allow));
        assertEq(reason, ComplianceTypes.REASON_OK);
    }

    function test_ZeroAmountRequestStillEvaluatesEligibility() public {
        // A zero-amount request is a pure eligibility question, so the cap check
        // must be skipped rather than treated as an allocation of zero.
        _seedPermissivePolicy(poolId);
        bytes32 ccid = _issue(SUBJECT, 1);

        (ComplianceTypes.Decision decision,) = sourceModule.evaluate(_request(ccid, poolId));
        assertEq(uint8(decision), uint8(ComplianceTypes.Decision.Allow));
    }

    // -----------------------------------------------------------------
    // System-level gates, which outrank everything
    // -----------------------------------------------------------------

    function test_PausedSystemDenies() public {
        _seedPermissivePolicy(poolId);
        bytes32 ccid = _issue(SUBJECT, 1);

        vm.prank(guardian);
        sourceEmergency.pause("incident");

        (ComplianceTypes.Decision decision, bytes32 reason) = sourceModule.evaluate(_request(ccid, poolId));

        // Fails closed: a system that cannot trust its own state must not report
        // that an investor is compliant.
        assertEq(uint8(decision), uint8(ComplianceTypes.Decision.Deny));
        assertEq(reason, ComplianceTypes.REASON_SYSTEM_PAUSED);
    }

    function test_SystemPausedOutranksCredentialBeingValid() public {
        // A healthy credential must not produce an allow while paused. If it did,
        // the pause would be useless precisely when it matters.
        _seedPermissivePolicy(poolId);
        bytes32 ccid = _issue(SUBJECT, 1);

        vm.prank(guardian);
        sourceEmergency.pause("incident");

        (ComplianceTypes.Decision decision,) = sourceModule.evaluate(_request(ccid, poolId));
        assertEq(uint8(decision), uint8(ComplianceTypes.Decision.Deny));
        assertFalse(sourceModule.isCredentialEligible(ccid) == false, "credential itself is still fine");
    }

    // -----------------------------------------------------------------
    // Pool policy gates
    // -----------------------------------------------------------------

    function test_UnknownPoolDenied() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        (ComplianceTypes.Decision decision, bytes32 reason) =
            sourceModule.evaluate(_request(ccid, keccak256("pool.nonexistent")));

        assertEq(uint8(decision), uint8(ComplianceTypes.Decision.Deny));
        assertEq(reason, ComplianceTypes.REASON_POOL_NOT_REGISTERED);
    }

    function test_RegisteredButInactivePolicyDenied() public {
        ComplianceTypes.InvestorClass[] memory classes = new ComplianceTypes.InvestorClass[](1);
        classes[0] = ComplianceTypes.InvestorClass.USAccredited;
        _seedPolicy(poolId, false, new uint16[](0), classes, false, 0, 0, ComplianceTypes.RevocationMode.IssuerOnly);
        bytes32 ccid = _issue(SUBJECT, 1);

        vm.prank(admin);
        sourcePolicies.deactivateActivePolicy(poolId);

        (ComplianceTypes.Decision decision, bytes32 reason) = sourceModule.evaluate(_request(ccid, poolId));
        assertEq(uint8(decision), uint8(ComplianceTypes.Decision.Deny));
        assertEq(reason, ComplianceTypes.REASON_POLICY_INACTIVE);
    }

    function test_PolicyRegisteredButNotYetActivatedDenied() public {
        // The activation delay is only meaningful if the window is closed. A policy
        // that exists but is not active must deny - and must say so distinctly, so
        // an integrator can tell "you have not deployed yet" from "your pool is off".
        ComplianceTypes.InvestorClass[] memory classes = new ComplianceTypes.InvestorClass[](1);
        classes[0] = ComplianceTypes.InvestorClass.USAccredited;

        vm.prank(admin);
        sourcePolicies.registerPolicy(
            poolId, false, new uint16[](0), classes, false, 0, 0, ComplianceTypes.RevocationMode.IssuerOnly, 0
        );
        bytes32 ccid = _issue(SUBJECT, 1);

        assertTrue(sourcePolicies.hasAnyPolicy(poolId), "a version is registered");
        assertFalse(sourcePolicies.hasActivePolicy(poolId), "but not active");

        (ComplianceTypes.Decision decision, bytes32 reason) = sourceModule.evaluate(_request(ccid, poolId));
        assertEq(uint8(decision), uint8(ComplianceTypes.Decision.Deny));
        assertEq(reason, ComplianceTypes.REASON_POLICY_INACTIVE);
    }

    // -----------------------------------------------------------------
    // Credential lifecycle
    // -----------------------------------------------------------------

    function test_MissingCredentialDenied() public {
        _seedPermissivePolicy(poolId);
        (ComplianceTypes.Decision decision, bytes32 reason) =
            sourceModule.evaluate(_request(keccak256("never-issued"), poolId));

        assertEq(uint8(decision), uint8(ComplianceTypes.Decision.Deny));
        assertEq(reason, ComplianceTypes.REASON_NO_CREDENTIAL);
    }

    function test_PendingCredentialDeniedNotProvisionallyAllowed() public {
        // The single most important negative test in the suite. If `Pending` were
        // treated as "probably fine", every unverified credential would pass.
        //
        // Removing the `Pending` check in isolation does *not* break this system: a
        // `Pending` record carries no provider, so `backsExistingCredentials(0)` denies
        // it two steps later. That is defence in depth, and it is why
        // `scripts/mutation-check.mjs` carries M1b, which removes both checks at once.
        _seedPermissivePolicy(poolId);
        ComplianceTypes.CredentialResult memory r = _defaultResult(SUBJECT, 1);

        vm.prank(workflow);
        sourceGateway.beginVerification(r.ccid, CRED_TYPE, SCHEMA_VERSION, TTL);

        (ComplianceTypes.Decision decision, bytes32 reason) = sourceModule.evaluate(_request(r.ccid, poolId));
        assertEq(uint8(decision), uint8(ComplianceTypes.Decision.Deny));
        assertEq(reason, ComplianceTypes.REASON_PENDING);

        // ...and the backstop is real, not merely assumed.
        ComplianceTypes.ComplianceCredential memory stored = sourceRegistry.getRecord(r.ccid);
        assertEq(stored.providerId, bytes32(0), "a pending record carries no provider");
        assertFalse(sourceProviders.backsExistingCredentials(stored.providerId));
    }

    function test_RevokedCredentialDenied() public {
        _seedPermissivePolicy(poolId);
        bytes32 ccid = _issue(SUBJECT, 1);
        vm.prank(issuer);
        sourceGateway.revoke(ccid, poolId, bytes32("aml"), new uint64[](0));

        (ComplianceTypes.Decision decision, bytes32 reason) = sourceModule.evaluate(_request(ccid, poolId));
        assertEq(uint8(decision), uint8(ComplianceTypes.Decision.Deny));
        assertEq(reason, ComplianceTypes.REASON_REVOKED);
    }

    function test_RevocationReportedEvenWhenExpiryWouldAlsoHavePassed() public {
        // Revocation is the more deliberate signal, so it is the one reported.
        _seedPermissivePolicy(poolId);
        bytes32 ccid = _issue(SUBJECT, 1);
        vm.prank(issuer);
        sourceGateway.revoke(ccid, poolId, bytes32("aml"), new uint64[](0));

        vm.warp(block.timestamp + TTL + 1);

        (, bytes32 reason) = sourceModule.evaluate(_request(ccid, poolId));
        assertEq(reason, ComplianceTypes.REASON_REVOKED);
    }

    function test_SuspendedCredentialDenied() public {
        _seedPermissivePolicy(poolId);
        bytes32 ccid = _issue(SUBJECT, 1);
        vm.prank(issuer);
        sourceGateway.suspend(ccid, bytes32("review"), new uint64[](0));

        (ComplianceTypes.Decision decision, bytes32 reason) = sourceModule.evaluate(_request(ccid, poolId));
        assertEq(uint8(decision), uint8(ComplianceTypes.Decision.Deny));
        assertEq(reason, ComplianceTypes.REASON_SUSPENDED);
    }

    function test_ExpiredCredentialDenied() public {
        _seedPermissivePolicy(poolId);
        bytes32 ccid = _issue(SUBJECT, 1);
        vm.warp(block.timestamp + TTL);

        (ComplianceTypes.Decision decision, bytes32 reason) = sourceModule.evaluate(_request(ccid, poolId));
        assertEq(uint8(decision), uint8(ComplianceTypes.Decision.Deny));
        assertEq(reason, ComplianceTypes.REASON_EXPIRED);
    }

    function test_RevokedOutranksExpired() public {
        _seedPermissivePolicy(poolId);
        bytes32 ccid = _issue(SUBJECT, 1);
        vm.warp(block.timestamp + TTL);
        vm.prank(issuer);
        sourceGateway.revoke(ccid, poolId, bytes32("late-aml"), new uint64[](0));

        (, bytes32 reason) = sourceModule.evaluate(_request(ccid, poolId));
        assertEq(reason, ComplianceTypes.REASON_REVOKED);
    }

    // -----------------------------------------------------------------
    // Provider standing
    // -----------------------------------------------------------------

    function test_PausedProviderDeniesExistingCredential() public {
        _seedPermissivePolicy(poolId);
        bytes32 ccid = _issue(SUBJECT, 1);

        vm.prank(admin);
        sourceProviders.setProviderStatus(PROVIDER_A, ProviderRegistry.ProviderStatus.Paused);

        (ComplianceTypes.Decision decision, bytes32 reason) = sourceModule.evaluate(_request(ccid, poolId));
        assertEq(uint8(decision), uint8(ComplianceTypes.Decision.Deny));
        assertEq(reason, ComplianceTypes.REASON_PROVIDER_PAUSED);
    }

    function test_DeprecatedProviderStillBacksExistingCredentials() public {
        // The distinction that stops a routine provider migration from invalidating
        // every live credential. New issuance is blocked separately, by the
        // gateway's `isActive` check.
        _seedPermissivePolicy(poolId);
        bytes32 ccid = _issue(SUBJECT, 1);

        vm.prank(admin);
        sourceProviders.setProviderStatus(PROVIDER_A, ProviderRegistry.ProviderStatus.Deprecated);

        (ComplianceTypes.Decision decision, bytes32 reason) = sourceModule.evaluate(_request(ccid, poolId));
        assertEq(uint8(decision), uint8(ComplianceTypes.Decision.Allow));
        assertEq(reason, ComplianceTypes.REASON_OK);

        // ...but nothing new may be issued against it.
        ComplianceTypes.CredentialResult memory fresh = _defaultResult(keccak256("subject-new"), 1);
        vm.prank(workflow);
        vm.expectRevert();
        sourceGateway.submitCredentialResult(fresh);
    }

    function test_RevokedProviderDeniesEverything() public {
        _seedPermissivePolicy(poolId);
        bytes32 ccid = _issue(SUBJECT, 1);

        vm.prank(admin);
        sourceProviders.setProviderStatus(PROVIDER_A, ProviderRegistry.ProviderStatus.Revoked);

        (, bytes32 reason) = sourceModule.evaluate(_request(ccid, poolId));
        assertEq(reason, ComplianceTypes.REASON_PROVIDER_PAUSED);
    }

    // -----------------------------------------------------------------
    // Eligibility under policy
    // -----------------------------------------------------------------

    function test_JurisdictionNotAcceptedDenied() public {
        uint16[] memory jurisdictions = new uint16[](1);
        jurisdictions[0] = JURISDICTION_US;
        ComplianceTypes.InvestorClass[] memory classes = new ComplianceTypes.InvestorClass[](1);
        classes[0] = ComplianceTypes.InvestorClass.USAccredited;
        _seedPolicy(poolId, false, jurisdictions, classes, false, 0, 0, ComplianceTypes.RevocationMode.IssuerOnly);

        ComplianceTypes.CredentialResult memory r =
            _result(SUBJECT, 1, JURISDICTION_UK, ComplianceTypes.InvestorClass.USAccredited);
        vm.prank(workflow);
        sourceGateway.submitCredentialResult(r);

        (ComplianceTypes.Decision decision, bytes32 reason) = sourceModule.evaluate(_request(r.ccid, poolId));
        assertEq(uint8(decision), uint8(ComplianceTypes.Decision.Deny));
        assertEq(reason, ComplianceTypes.REASON_JURISDICTION_BLOCKED);
    }

    function test_EmptyJurisdictionListMeansAllJurisdictions() public {
        ComplianceTypes.InvestorClass[] memory classes = new ComplianceTypes.InvestorClass[](1);
        classes[0] = ComplianceTypes.InvestorClass.USAccredited;
        _seedPolicy(poolId, false, new uint16[](0), classes, false, 0, 0, ComplianceTypes.RevocationMode.IssuerOnly);

        ComplianceTypes.CredentialResult memory r = _result(SUBJECT, 1, 392, ComplianceTypes.InvestorClass.USAccredited); // Japan
        vm.prank(workflow);
        sourceGateway.submitCredentialResult(r);

        (ComplianceTypes.Decision decision,) = sourceModule.evaluate(_request(r.ccid, poolId));
        assertEq(uint8(decision), uint8(ComplianceTypes.Decision.Allow));
    }

    function test_InvestorClassNotAcceptedDenied() public {
        ComplianceTypes.InvestorClass[] memory classes = new ComplianceTypes.InvestorClass[](1);
        classes[0] = ComplianceTypes.InvestorClass.USAccredited;
        _seedPolicy(poolId, false, new uint16[](0), classes, false, 0, 0, ComplianceTypes.RevocationMode.IssuerOnly);

        ComplianceTypes.CredentialResult memory r =
            _result(SUBJECT, 1, JURISDICTION_US, ComplianceTypes.InvestorClass.NonUSProfessional);
        vm.prank(workflow);
        sourceGateway.submitCredentialResult(r);

        (ComplianceTypes.Decision decision, bytes32 reason) = sourceModule.evaluate(_request(r.ccid, poolId));
        assertEq(uint8(decision), uint8(ComplianceTypes.Decision.Deny));
        assertEq(reason, ComplianceTypes.REASON_INVESTOR_CLASS_BLOCKED);
    }

    function test_BlockedInvestorNeverImplicitlyAccepted() public {
        // An empty class list means "all except Blocked". Serving a blocked
        // investor must require an explicit opt-in.
        ComplianceTypes.InvestorClass[] memory classes = new ComplianceTypes.InvestorClass[](2);
        classes[0] = ComplianceTypes.InvestorClass.USAccredited;
        classes[1] = ComplianceTypes.InvestorClass.NonUSProfessional;
        _seedPolicy(poolId, false, new uint16[](0), classes, false, 0, 0, ComplianceTypes.RevocationMode.IssuerOnly);

        ComplianceTypes.CredentialResult memory r =
            _result(SUBJECT, 1, JURISDICTION_US, ComplianceTypes.InvestorClass.Blocked);
        vm.prank(workflow);
        sourceGateway.submitCredentialResult(r);

        (, bytes32 reason) = sourceModule.evaluate(_request(r.ccid, poolId));
        assertEq(reason, ComplianceTypes.REASON_INVESTOR_CLASS_BLOCKED);
    }

    function test_BlockedInvestorAcceptedWhenExplicitlyOptedIn() public {
        ComplianceTypes.InvestorClass[] memory classes = new ComplianceTypes.InvestorClass[](1);
        classes[0] = ComplianceTypes.InvestorClass.Blocked;
        _seedPolicy(poolId, false, new uint16[](0), classes, false, 0, 0, ComplianceTypes.RevocationMode.IssuerOnly);

        ComplianceTypes.CredentialResult memory r =
            _result(SUBJECT, 1, JURISDICTION_US, ComplianceTypes.InvestorClass.Blocked);
        vm.prank(workflow);
        sourceGateway.submitCredentialResult(r);

        (ComplianceTypes.Decision decision,) = sourceModule.evaluate(_request(r.ccid, poolId));
        assertEq(uint8(decision), uint8(ComplianceTypes.Decision.Allow));
    }

    // -----------------------------------------------------------------
    // Allocation cap
    // -----------------------------------------------------------------

    function test_AllocationCapEnforcedAgainstTotalNotIncrement() public {
        // The reason `currentAllocation` is a parameter at all. Checking only the
        // increment would let a holder already at the cap add another cap's worth.
        uint256 cap = 1000e18;
        ComplianceTypes.InvestorClass[] memory classes = new ComplianceTypes.InvestorClass[](1);
        classes[0] = ComplianceTypes.InvestorClass.USAccredited;
        _seedPolicy(poolId, false, new uint16[](0), classes, false, 0, cap, ComplianceTypes.RevocationMode.IssuerOnly);
        bytes32 ccid = _issue(SUBJECT, 1);

        (ComplianceTypes.Decision decision, bytes32 reason) =
            sourceModule.evaluate(_requestWithAmount(ccid, poolId, 400e18, 700e18));
        assertEq(uint8(decision), uint8(ComplianceTypes.Decision.Deny));
        assertEq(reason, ComplianceTypes.REASON_ALLOCATION_CAP_EXCEEDED);

        // Under the cap, the same increment is fine.
        (ComplianceTypes.Decision ok,) = sourceModule.evaluate(_requestWithAmount(ccid, poolId, 300e18, 700e18));
        assertEq(uint8(ok), uint8(ComplianceTypes.Decision.Allow));
    }

    function test_ZeroCapMeansUncapped() public {
        ComplianceTypes.InvestorClass[] memory classes = new ComplianceTypes.InvestorClass[](1);
        classes[0] = ComplianceTypes.InvestorClass.USAccredited;
        _seedPolicy(poolId, false, new uint16[](0), classes, false, 0, 0, ComplianceTypes.RevocationMode.IssuerOnly);
        bytes32 ccid = _issue(SUBJECT, 1);

        (ComplianceTypes.Decision decision,) =
            sourceModule.evaluate(_requestWithAmount(ccid, poolId, type(uint256).max, 0));
        assertEq(uint8(decision), uint8(ComplianceTypes.Decision.Allow));
    }

    function test_CapBoundaryIsInclusive() public {
        uint256 cap = 1000e18;
        ComplianceTypes.InvestorClass[] memory classes = new ComplianceTypes.InvestorClass[](1);
        classes[0] = ComplianceTypes.InvestorClass.USAccredited;
        _seedPolicy(poolId, false, new uint16[](0), classes, false, 0, cap, ComplianceTypes.RevocationMode.IssuerOnly);
        bytes32 ccid = _issue(SUBJECT, 1);

        (ComplianceTypes.Decision atCap,) = sourceModule.evaluate(_requestWithAmount(ccid, poolId, 500e18, 500e18));
        assertEq(uint8(atCap), uint8(ComplianceTypes.Decision.Allow));
    }

    // -----------------------------------------------------------------
    // Manual review
    // -----------------------------------------------------------------

    function test_ManualReviewIsNotAnAllow() public {
        ComplianceTypes.InvestorClass[] memory classes = new ComplianceTypes.InvestorClass[](1);
        classes[0] = ComplianceTypes.InvestorClass.USAccredited;
        _seedPolicy(poolId, true, new uint16[](0), classes, false, 0, 0, ComplianceTypes.RevocationMode.IssuerOnly);
        bytes32 ccid = _issue(SUBJECT, 1);

        (ComplianceTypes.Decision decision, bytes32 reason) = sourceModule.evaluate(_request(ccid, poolId));
        assertEq(uint8(decision), uint8(ComplianceTypes.Decision.ReviewRequired));
        assertEq(reason, ComplianceTypes.REASON_MANUAL_REVIEW_REQUIRED);
    }

    function test_ReviewRequirementDoesNotMaskARealDenial() public {
        // Review is a routing instruction, so it must never be the reported reason
        // when something is actually wrong. An integrator that routes on the reason
        // code would otherwise send a suspended credential to a review queue.
        ComplianceTypes.InvestorClass[] memory classes = new ComplianceTypes.InvestorClass[](1);
        classes[0] = ComplianceTypes.InvestorClass.USAccredited;
        _seedPolicy(poolId, true, new uint16[](0), classes, false, 0, 0, ComplianceTypes.RevocationMode.IssuerOnly);
        bytes32 ccid = _issue(SUBJECT, 1);
        vm.prank(issuer);
        sourceGateway.suspend(ccid, bytes32("review"), new uint64[](0));

        (ComplianceTypes.Decision decision, bytes32 reason) = sourceModule.evaluate(_request(ccid, poolId));
        assertEq(uint8(decision), uint8(ComplianceTypes.Decision.Deny));
        assertEq(reason, ComplianceTypes.REASON_SUSPENDED);
    }

    // -----------------------------------------------------------------
    // Replica freshness
    // -----------------------------------------------------------------

    function test_StaleReplicaDenied() public {
        // A destination system, so the replica is evaluated where it actually lives.
        AuditTrail destAudit = new AuditTrail(admin);
        PoolComplianceModule destModule =
            new PoolComplianceModule(destRegistry, destProviders, destPolicies, destEmergency, destAudit);

        ComplianceTypes.InvestorClass[] memory classes = new ComplianceTypes.InvestorClass[](1);
        classes[0] = ComplianceTypes.InvestorClass.USAccredited;
        _seedDestPolicy(classes, true, 1 days);

        bytes32 ccid = _issueAndPropagate(SUBJECT, 1, JURISDICTION_US, ComplianceTypes.InvestorClass.USAccredited);

        // Within tolerance: allowed.
        (ComplianceTypes.Decision fresh,) = destModule.evaluate(_request(ccid, keccak256("pool.dest")));
        assertEq(uint8(fresh), uint8(ComplianceTypes.Decision.Allow));

        // Past tolerance: denied. Nothing about the credential itself changed - this
        // is purely about how long the destination has been unable to confirm.
        vm.warp(block.timestamp + 2 days);
        (ComplianceTypes.Decision stale, bytes32 reason) = destModule.evaluate(_request(ccid, keccak256("pool.dest")));
        assertEq(uint8(stale), uint8(ComplianceTypes.Decision.Deny));
        assertEq(reason, ComplianceTypes.REASON_STALE_DESTINATION);
    }

    function test_FreshnessNotEnforcedWhenPolicyDoesNotRequireIt() public {
        AuditTrail destAudit = new AuditTrail(admin);
        PoolComplianceModule destModule =
            new PoolComplianceModule(destRegistry, destProviders, destPolicies, destEmergency, destAudit);

        ComplianceTypes.InvestorClass[] memory classes = new ComplianceTypes.InvestorClass[](1);
        classes[0] = ComplianceTypes.InvestorClass.USAccredited;
        _seedDestPolicy(classes, false, 0);

        bytes32 ccid = _issueAndPropagate(SUBJECT, 1, JURISDICTION_US, ComplianceTypes.InvestorClass.USAccredited);

        vm.warp(block.timestamp + 365 days);
        (ComplianceTypes.Decision decision, bytes32 reason) =
            destModule.evaluate(_request(ccid, keccak256("pool.dest")));
        // Expired on its own terms, but *not* reported as stale: the freshness rule
        // is opt-in, and conflating the two would make a real expiry hard to spot.
        assertEq(uint8(decision), uint8(ComplianceTypes.Decision.Deny));
        assertEq(reason, ComplianceTypes.REASON_EXPIRED);
    }

    // -----------------------------------------------------------------
    // isCredentialEligible: credential health, not request health
    // -----------------------------------------------------------------

    function test_IsCredentialEligibleIgnoresPoolPolicy() public {
        // No policy registered at all. The credential is fine; the *request*
        // is not answerable. Conflating the two sends holders to re-verify for
        // nothing.
        bytes32 ccid = _issue(SUBJECT, 1);
        assertFalse(sourcePolicies.hasActivePolicy(poolId));
        assertTrue(sourceModule.isCredentialEligible(ccid));
    }

    function test_IsCredentialEligibleFalseWhenProviderRevoked() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        vm.prank(admin);
        sourceProviders.setProviderStatus(PROVIDER_A, ProviderRegistry.ProviderStatus.Revoked);
        assertFalse(sourceModule.isCredentialEligible(ccid));
    }

    function test_IsCredentialEligibleFalseWhenExpired() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        vm.warp(block.timestamp + TTL);
        assertFalse(sourceModule.isCredentialEligible(ccid));
    }

    // -----------------------------------------------------------------
    // Recording
    // -----------------------------------------------------------------

    function test_EvaluateAndRecordEmitsOnAllow() public {
        _seedPermissivePolicy(poolId);
        bytes32 ccid = _issue(SUBJECT, 1);

        // The event names `msg.sender`, so it is the test contract that must appear
        // here - not any of the fixture actors.
        uint256 before = sourceAudit.totalEntries();
        vm.expectEmit(true, true, true, true, address(sourceModule));
        emit PoolComplianceModule.AccessAllowed(ccid, poolId, address(this), ComplianceTypes.REASON_OK, 0);
        (ComplianceTypes.Decision decision,) = sourceModule.evaluateAndRecord(_request(ccid, poolId));
        assertEq(uint8(decision), uint8(ComplianceTypes.Decision.Allow));

        // ...and the same decision is written to the trail, with the actor as the
        // audit entry's subject rather than a free-standing address.
        //
        // Measured as a delta: issuance and policy registration also write entries,
        // so an absolute index would be asserting on the fixture's history rather
        // than on this call's behaviour.
        assertEq(sourceAudit.totalEntries(), before + 1);
        AuditTrail.Entry memory entry = sourceAudit.getEntry(before);
        assertEq(uint8(entry.kind), uint8(AuditTrail.EntryKind.AccessAllowed));
        assertEq(entry.ccid, ccid);
        assertEq(entry.actor, bytes32(uint256(uint160(address(this)))));
        assertEq(entry.reasonCode, ComplianceTypes.REASON_OK);
    }

    function test_EvaluateAndRecordEmitsReviewRequired() public {
        ComplianceTypes.InvestorClass[] memory classes = new ComplianceTypes.InvestorClass[](1);
        classes[0] = ComplianceTypes.InvestorClass.USAccredited;
        _seedPolicy(poolId, true, new uint16[](0), classes, false, 0, 0, ComplianceTypes.RevocationMode.IssuerOnly);
        bytes32 ccid = _issue(SUBJECT, 1);

        vm.expectEmit(true, true, true, true, address(sourceModule));
        emit PoolComplianceModule.AccessReviewRequired(
            ccid, poolId, address(this), ComplianceTypes.REASON_MANUAL_REVIEW_REQUIRED
        );
        (ComplianceTypes.Decision decision,) = sourceModule.evaluateAndRecord(_request(ccid, poolId));
        assertEq(uint8(decision), uint8(ComplianceTypes.Decision.ReviewRequired));

        uint256 before = sourceAudit.totalEntries();
        sourceModule.evaluateAndRecord(_request(ccid, poolId));
        assertEq(sourceAudit.totalEntries(), before + 1);
        assertEq(uint8(sourceAudit.getEntry(before).kind), uint8(AuditTrail.EntryKind.ReviewRequired));
    }

    function test_EvaluateAndRecordEmitsNothingOnDenial() public {
        // A public denial history would let anyone inflate a holder's record by
        // probing. The reason is returned to the caller; the trail is not written.
        bytes32 ccid = _issue(SUBJECT, 1);
        uint256 before = sourceAudit.totalEntries();

        (ComplianceTypes.Decision decision,) =
            sourceModule.evaluateAndRecord(_request(ccid, keccak256("pool.nonexistent")));
        assertEq(uint8(decision), uint8(ComplianceTypes.Decision.Deny));
        assertEq(sourceAudit.totalEntries(), before);
    }

    // -----------------------------------------------------------------
    // Reason-code surface
    // -----------------------------------------------------------------

    /**
     * @dev Every *declared* reason code resolves to its own name.
     *
     *      Written against the declarations rather than {ComplianceTypes.allReasons} on
     *      purpose. The previous version iterated that function and compared the count to
     *      a literal - which passed while `POOL_NOT_REGISTERED` was missing from the list
     *      entirely, so `describeReason` answered `UNRECOGNIZED` for a reason the module
     *      genuinely returns. A test that takes its expectation from the thing it is
     *      testing cannot detect that the thing is incomplete; this one does.
     */
    function test_EveryDeclaredReasonCodeHasALabel() public view {
        bytes32[15] memory declared = [
            ComplianceTypes.REASON_OK,
            ComplianceTypes.REASON_NO_CREDENTIAL,
            ComplianceTypes.REASON_PENDING,
            ComplianceTypes.REASON_EXPIRED,
            ComplianceTypes.REASON_SUSPENDED,
            ComplianceTypes.REASON_REVOKED,
            ComplianceTypes.REASON_JURISDICTION_BLOCKED,
            ComplianceTypes.REASON_INVESTOR_CLASS_BLOCKED,
            ComplianceTypes.REASON_STALE_DESTINATION,
            ComplianceTypes.REASON_ALLOCATION_CAP_EXCEEDED,
            ComplianceTypes.REASON_MANUAL_REVIEW_REQUIRED,
            ComplianceTypes.REASON_POOL_NOT_REGISTERED,
            ComplianceTypes.REASON_POLICY_INACTIVE,
            ComplianceTypes.REASON_PROVIDER_PAUSED,
            ComplianceTypes.REASON_SYSTEM_PAUSED
        ];

        for (uint256 i = 0; i < declared.length; ++i) {
            string memory label = sourceModule.describeReason(declared[i]);
            assertTrue(bytes(label).length > 0, "reason label must not be empty");
            assertTrue(
                keccak256(bytes(label)) != keccak256("UNRECOGNIZED"), "every declared code must resolve to a real label"
            );
        }

        // ...and the curated list must contain all of them, each exactly once.
        bytes32[] memory curated = ComplianceTypes.allReasons();
        assertEq(curated.length, declared.length, "allReasons must list every declared code exactly once");
        for (uint256 i = 0; i < declared.length; ++i) {
            uint256 seen;
            for (uint256 j = 0; j < curated.length; ++j) {
                if (curated[j] == declared[i]) ++seen;
            }
            assertEq(seen, 1, "each declared code appears exactly once in allReasons");
        }
    }

    /**
     * @dev `POOL_NOT_REGISTERED` labels as itself.
     *
     *      The specific regression, kept as its own test so a failure names the code that
     *      broke rather than pointing at a loop index. It is the reason an integrator most
     *      often needs to render correctly - "this pool has no policy configured" is a
     *      configuration mistake, not a statement about the holder.
     */
    function test_PoolNotRegisteredReasonIsLabelled() public view {
        assertEq(sourceModule.describeReason(ComplianceTypes.REASON_POOL_NOT_REGISTERED), "POOL_NOT_REGISTERED");
    }

    function test_UnknownReasonCodeLabelsAsUnrecognized() public view {
        // A newer contract must not brick an older SDK's logging path.
        assertEq(sourceModule.describeReason(keccak256("FROM_THE_FUTURE")), "UNRECOGNIZED");
    }

    function test_OnlyOkIsAnAllow() public {
        // The one correct way to branch on a decision. If any other code ever
        // reported as an allow, `isAllow` would have to change with it.
        bytes32[] memory codes = ComplianceTypes.allReasons();
        for (uint256 i = 0; i < codes.length; ++i) {
            if (i == 0) {
                assertTrue(ComplianceTypes.isAllow(codes[i]), "OK is the only allow");
            } else {
                assertFalse(ComplianceTypes.isAllow(codes[i]), "only OK is an allow");
            }
        }
    }

    function test_OnlyManualReviewIsReviewRequired() public {
        bytes32[] memory codes = ComplianceTypes.allReasons();
        uint256 seen;
        for (uint256 i = 0; i < codes.length; ++i) {
            if (ComplianceTypes.isReviewRequired(codes[i])) {
                assertEq(codes[i], ComplianceTypes.REASON_MANUAL_REVIEW_REQUIRED);
                ++seen;
            }
        }
        assertEq(seen, 1);
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    function _seedDestPolicy(ComplianceTypes.InvestorClass[] memory classes, bool requiresFresh, uint64 maxReplicaAge)
        internal
    {
        bytes32 destPool = keccak256("pool.dest");
        vm.startPrank(admin);
        uint32 next = destPolicies.latestVersion(destPool) + 1;
        destPolicies.registerPolicy(
            destPool,
            false,
            new uint16[](0),
            classes,
            requiresFresh,
            maxReplicaAge,
            0,
            ComplianceTypes.RevocationMode.IssuerOnly,
            0
        );
        vm.warp(block.timestamp + destPolicies.POLICY_ACTIVATION_DELAY() + 1);
        destPolicies.activatePolicyVersion(destPool, next);
        vm.stopPrank();
    }

    /**
     * @dev Issue a credential *with* a destination selector, so the propagation
     *      happens as part of issuance rather than as a second submission.
     *
     *      Submitting a second result to trigger propagation would need a fresh
     *      nonce and would be rejected by the gateway's own monotonicity check -
     *      which is the correct behaviour, and a reminder that propagation rides
     *      along with the write rather than being a separate action.
     */
    function _issueAndPropagate(
        bytes32 subjectCommitment,
        uint64 nonce,
        uint16 jurisdiction,
        ComplianceTypes.InvestorClass investorClass
    ) internal returns (bytes32 ccid) {
        uint64[] memory dests = new uint64[](1);
        dests[0] = DEST_SELECTOR;

        ComplianceTypes.CredentialResult memory r = _result(subjectCommitment, nonce, jurisdiction, investorClass);
        r.destinationChainSelectors = dests;

        uint256 sentBefore = router.sentCount();
        vm.prank(workflow);
        sourceGateway.submitCredentialResult(r);
        ccid = r.ccid;

        // The router recorded exactly one message; deliver it as the destination chain.
        assertEq(router.sentCount(), sentBefore + 1);
        _deliver(sentBefore, address(sourceGateway), keccak256("order-1"));
    }
}
