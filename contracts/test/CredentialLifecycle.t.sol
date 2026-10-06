// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ComplianceGateway} from "../src/ComplianceGateway.sol";
import {ComplianceRegistry} from "../src/ComplianceRegistry.sol";
import {ProviderRegistry} from "../src/ProviderRegistry.sol";
import {ComplianceTypes} from "../src/libraries/ComplianceTypes.sol";
import {ComplianceTestBase} from "./helpers/ComplianceTestBase.sol";

/**
 * @title CredentialLifecycleTest
 * @notice Issue, renew, suspend, resume, revoke, expire, and query on the source
 *         chain, plus every issuance-time rejection the gateway is responsible for.
 */
contract CredentialLifecycleTest is ComplianceTestBase {
    bytes32 internal poolId = keccak256("pool.treasury");

    // -----------------------------------------------------------------
    // Issue
    // -----------------------------------------------------------------

    function test_IssueStoresMinimalRecord() public {
        bytes32 ccid = _issue(SUBJECT, 1);

        assertTrue(sourceRegistry.exists(ccid));
        assertEq(uint8(sourceRegistry.statusOf(ccid)), uint8(ComplianceTypes.CredentialStatus.Valid));

        ComplianceTypes.ComplianceCredential memory r = sourceRegistry.getRecord(ccid);
        assertEq(r.credentialType, CRED_TYPE);
        assertEq(r.providerId, PROVIDER_A);
        assertEq(r.evidenceHash, EVIDENCE);
        assertEq(r.schemaVersion, SCHEMA_VERSION);
        assertEq(r.jurisdictionCode, JURISDICTION_US);
        assertEq(uint8(r.investorClass), uint8(ComplianceTypes.InvestorClass.USAccredited));
        assertEq(r.nonce, 1);
        assertEq(r.expiresAt, uint64(block.timestamp) + TTL);
    }

    function test_IssueRecordsJurisdictionAndClass() public {
        ComplianceTypes.CredentialResult memory r =
            _result(SUBJECT, 1, JURISDICTION_UK, ComplianceTypes.InvestorClass.NonUSProfessional);
        vm.prank(workflow);
        sourceGateway.submitCredentialResult(r);

        ComplianceTypes.ComplianceCredential memory stored = sourceRegistry.getRecord(r.ccid);
        assertEq(stored.jurisdictionCode, JURISDICTION_UK);
        assertEq(uint8(stored.investorClass), uint8(ComplianceTypes.InvestorClass.NonUSProfessional));
    }

    function test_BlockedInvestorCanBeCredentialedButNeverImplicitlyAccepted() public {
        // A Blocked credential is representable, so a denial is explainable. Whether
        // a pool serves it is a policy decision, enforced in the module suite.
        ComplianceTypes.CredentialResult memory r =
            _result(SUBJECT, 1, JURISDICTION_US, ComplianceTypes.InvestorClass.Blocked);
        vm.prank(workflow);
        sourceGateway.submitCredentialResult(r);
        assertTrue(sourceRegistry.isValid(r.ccid));
    }

    function test_UnauthorizedSubmitterRejected() public {
        ComplianceTypes.CredentialResult memory r = _defaultResult(SUBJECT, 1);
        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(ComplianceGateway.NotAuthorized.selector, outsider));
        sourceGateway.submitCredentialResult(r);
    }

    function test_TamperedCcidRejected() public {
        ComplianceTypes.CredentialResult memory r = _defaultResult(SUBJECT, 1);
        r.ccid = keccak256("not-the-real-ccid");
        vm.prank(workflow);
        vm.expectRevert();
        sourceGateway.submitCredentialResult(r);
    }

    function test_SubjectSwapRejected() public {
        // A CCID computed for one subject, submitted with another's commitment.
        ComplianceTypes.CredentialResult memory r = _defaultResult(SUBJECT, 1);
        r.subjectCommitment = keccak256("subject-commitment-bob");
        vm.prank(workflow);
        vm.expectRevert();
        sourceGateway.submitCredentialResult(r);
    }

    function test_JurisdictionSwapRejected() public {
        // Changing the jurisdiction changes the CCID, so an accreditation claimed
        // for one country cannot be presented as another's.
        ComplianceTypes.CredentialResult memory r = _defaultResult(SUBJECT, 1);
        r.jurisdictionCode = JURISDICTION_UK;
        vm.prank(workflow);
        vm.expectRevert();
        sourceGateway.submitCredentialResult(r);
    }

    function test_InvestorClassEscalationRejected() public {
        // A non-professional credential cannot be relabelled as accredited.
        ComplianceTypes.CredentialResult memory r =
            _result(SUBJECT, 1, JURISDICTION_US, ComplianceTypes.InvestorClass.NonUSProfessional);
        vm.prank(workflow);
        sourceGateway.submitCredentialResult(r);

        ComplianceTypes.CredentialResult memory escalated = _defaultResult(SUBJECT, 1);
        escalated.ccid = r.ccid; // try to reuse the existing identity
        vm.prank(workflow);
        vm.expectRevert();
        sourceGateway.submitCredentialResult(escalated);
    }

    function test_PausedProviderRejected() public {
        vm.prank(admin);
        sourceProviders.setProviderStatus(PROVIDER_A, ProviderRegistry.ProviderStatus.Paused);
        ComplianceTypes.CredentialResult memory r = _defaultResult(SUBJECT, 1);
        vm.prank(workflow);
        vm.expectRevert();
        sourceGateway.submitCredentialResult(r);
    }

    function test_UnadmittedProviderRejected() public {
        ComplianceTypes.CredentialResult memory r = _defaultResult(SUBJECT, 1);
        r.providerId = keccak256("provider.not-admitted");
        vm.prank(workflow);
        vm.expectRevert();
        sourceGateway.submitCredentialResult(r);
    }

    function test_UnsetJurisdictionRejected() public {
        ComplianceTypes.CredentialResult memory r = _result(SUBJECT, 1, 0, ComplianceTypes.InvestorClass.USAccredited);
        vm.prank(workflow);
        vm.expectRevert();
        sourceGateway.submitCredentialResult(r);
    }

    function test_UnknownInvestorClassRejected() public {
        ComplianceTypes.CredentialResult memory r =
            _result(SUBJECT, 1, JURISDICTION_US, ComplianceTypes.InvestorClass.Unknown);
        vm.prank(workflow);
        vm.expectRevert();
        sourceGateway.submitCredentialResult(r);
    }

    function test_ZeroEvidenceHashRejected() public {
        ComplianceTypes.CredentialResult memory r = _defaultResult(SUBJECT, 1);
        r.evidenceHash = bytes32(0);
        vm.prank(workflow);
        vm.expectRevert();
        sourceGateway.submitCredentialResult(r);
    }

    function test_ExpiryInPastRejected() public {
        ComplianceTypes.CredentialResult memory r = _defaultResult(SUBJECT, 1);
        r.issuedAt = uint64(block.timestamp) - TTL - 1;
        r.expiresAt = r.issuedAt + TTL;
        vm.prank(workflow);
        vm.expectRevert();
        sourceGateway.submitCredentialResult(r);
    }

    function test_ReissueWithSameNonceRejected() public {
        ComplianceTypes.CredentialResult memory r = _defaultResult(SUBJECT, 1);
        vm.prank(workflow);
        sourceGateway.submitCredentialResult(r);

        vm.prank(workflow);
        vm.expectRevert();
        sourceGateway.submitCredentialResult(r);
    }

    function test_PendingThenResolved() public {
        ComplianceTypes.CredentialResult memory r = _defaultResult(SUBJECT, 1);
        vm.prank(workflow);
        sourceGateway.beginVerification(r.ccid, CRED_TYPE, SCHEMA_VERSION, TTL);

        assertEq(uint8(sourceRegistry.statusOf(r.ccid)), uint8(ComplianceTypes.CredentialStatus.Pending));

        vm.prank(workflow);
        sourceGateway.submitCredentialResult(r);
        assertEq(uint8(sourceRegistry.statusOf(r.ccid)), uint8(ComplianceTypes.CredentialStatus.Valid));
    }

    // -----------------------------------------------------------------
    // Expiry
    // -----------------------------------------------------------------

    function test_LazyExpiryWithoutSweeper() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        assertTrue(sourceRegistry.isValid(ccid));

        vm.warp(block.timestamp + TTL);
        assertEq(uint8(sourceRegistry.statusOf(ccid)), uint8(ComplianceTypes.CredentialStatus.Expired));
        assertFalse(sourceRegistry.isValid(ccid));
    }

    function test_SweeperMarksExpired() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        vm.warp(block.timestamp + TTL);

        bytes32[] memory ccids = new bytes32[](1);
        ccids[0] = ccid;
        vm.prank(address(sourceGateway));
        assertEq(sourceRegistry.expireDue(ccids), 1);
    }

    function test_SweeperIsIdempotent() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        vm.warp(block.timestamp + TTL);
        bytes32[] memory ccids = new bytes32[](1);
        ccids[0] = ccid;

        vm.startPrank(address(sourceGateway));
        sourceRegistry.expireDue(ccids);
        assertEq(sourceRegistry.expireDue(ccids), 0);
        vm.stopPrank();
    }

    // -----------------------------------------------------------------
    // Renew
    // -----------------------------------------------------------------

    function test_RenewExtendsExpiry() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        uint64 oldExpiry = sourceRegistry.getRecord(ccid).expiresAt;

        vm.warp(block.timestamp + 10 days);
        ComplianceTypes.CredentialResult memory r = _defaultResult(SUBJECT, 2);
        vm.prank(workflow);
        sourceGateway.renewCredential(r, new uint64[](0), uint64(block.timestamp) + TTL, 2);

        assertGt(sourceRegistry.getRecord(ccid).expiresAt, oldExpiry);
        assertEq(sourceRegistry.getRecord(ccid).nonce, 2);
    }

    function test_RenewRecoversExpiredCredential() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        vm.warp(block.timestamp + TTL + 1);
        assertEq(uint8(sourceRegistry.statusOf(ccid)), uint8(ComplianceTypes.CredentialStatus.Expired));

        ComplianceTypes.CredentialResult memory r = _defaultResult(SUBJECT, 2);
        vm.prank(workflow);
        sourceGateway.renewCredential(r, new uint64[](0), uint64(block.timestamp) + TTL, 2);

        assertEq(uint8(sourceRegistry.statusOf(ccid)), uint8(ComplianceTypes.CredentialStatus.Valid));
    }

    function test_RenewRevokedRejected() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        _seedPermissivePolicy(poolId);
        vm.prank(issuer);
        sourceGateway.revoke(ccid, poolId, bytes32("test"), new uint64[](0));

        ComplianceTypes.CredentialResult memory r = _defaultResult(SUBJECT, 2);
        vm.prank(workflow);
        vm.expectRevert();
        sourceGateway.renewCredential(r, new uint64[](0), uint64(block.timestamp) + TTL, 2);
    }

    // -----------------------------------------------------------------
    // Suspend / resume
    // -----------------------------------------------------------------

    function test_SuspendAndResume() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        uint64[] memory dests = new uint64[](0);

        vm.prank(issuer);
        sourceGateway.suspend(ccid, bytes32("under-review"), dests);
        assertEq(uint8(sourceRegistry.statusOf(ccid)), uint8(ComplianceTypes.CredentialStatus.Suspended));

        vm.prank(issuer);
        sourceGateway.resume(ccid, bytes32("cleared"), dests);
        assertEq(uint8(sourceRegistry.statusOf(ccid)), uint8(ComplianceTypes.CredentialStatus.Valid));
    }

    function test_SuspendRequiresIssuer() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        vm.prank(outsider);
        vm.expectRevert();
        sourceGateway.suspend(ccid, bytes32("nope"), new uint64[](0));
    }

    // -----------------------------------------------------------------
    // Revocation
    // -----------------------------------------------------------------

    function test_RevokeByIssuer() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        _seedPermissivePolicy(poolId);
        vm.prank(issuer);
        sourceGateway.revoke(ccid, poolId, bytes32("aml-match"), new uint64[](0));
        assertEq(uint8(sourceRegistry.statusOf(ccid)), uint8(ComplianceTypes.CredentialStatus.Revoked));
    }

    function test_HolderCanAlwaysWithdrawTheirOwnCredential() public {
        // Checked before policy is consulted: a holder who cannot exit is trapped,
        // and a trap is not an acceptable way to enforce issuer policy.
        bytes32 ccid = _issue(SUBJECT, 1);
        vm.prank(holder);
        sourceGateway.revoke(ccid, bytes32(0), bytes32("self-withdrawal"), new uint64[](0));
        assertEq(uint8(sourceRegistry.statusOf(ccid)), uint8(ComplianceTypes.CredentialStatus.Revoked));
    }

    function test_GovernanceOnlyPolicyExcludesIssuer() public {
        ComplianceTypes.InvestorClass[] memory classes = new ComplianceTypes.InvestorClass[](1);
        classes[0] = ComplianceTypes.InvestorClass.USAccredited;
        _seedPolicy(poolId, false, new uint16[](0), classes, false, 0, 0, ComplianceTypes.RevocationMode.GovernanceOnly);

        bytes32 ccid = _issue(SUBJECT, 1);

        // The issuer alone cannot revoke under governance-only policy.
        vm.prank(issuer);
        vm.expectRevert();
        sourceGateway.revoke(ccid, poolId, bytes32("no"), new uint64[](0));

        // Governance can.
        vm.prank(admin);
        sourceGateway.revoke(ccid, poolId, bytes32("gov"), new uint64[](0));
        assertEq(uint8(sourceRegistry.statusOf(ccid)), uint8(ComplianceTypes.CredentialStatus.Revoked));
    }

    function test_OutsiderCannotRevoke() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        vm.prank(outsider);
        vm.expectRevert();
        sourceGateway.revoke(ccid, bytes32(0), bytes32("no"), new uint64[](0));
    }

    function test_RevocationIsTerminal() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        uint64[] memory dests = new uint64[](0);

        vm.prank(issuer);
        sourceGateway.revoke(ccid, bytes32(0), bytes32("fraud"), dests);

        vm.prank(issuer);
        vm.expectRevert();
        sourceGateway.suspend(ccid, bytes32("x"), dests);

        vm.prank(issuer);
        vm.expectRevert();
        sourceGateway.resume(ccid, bytes32("x"), dests);

        ComplianceTypes.CredentialResult memory r = _defaultResult(SUBJECT, 2);
        vm.prank(workflow);
        vm.expectRevert();
        sourceGateway.renewCredential(r, dests, uint64(block.timestamp) + TTL, 2);

        assertEq(uint8(sourceRegistry.statusOf(ccid)), uint8(ComplianceTypes.CredentialStatus.Revoked));
    }

    // -----------------------------------------------------------------
    // Query
    // -----------------------------------------------------------------

    function test_UnknownCredentialIsNotValid() public {
        bytes32 ccid = keccak256("never-issued");
        assertFalse(sourceRegistry.exists(ccid));
        assertEq(uint8(sourceRegistry.statusOf(ccid)), uint8(ComplianceTypes.CredentialStatus.Unknown));
        assertFalse(sourceRegistry.isValid(ccid));
    }

    function test_AgeOfTracksUpdates() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        assertEq(sourceRegistry.ageOf(ccid), 0);
        vm.warp(block.timestamp + 5 days);
        assertEq(sourceRegistry.ageOf(ccid), 5 days);
    }
}
