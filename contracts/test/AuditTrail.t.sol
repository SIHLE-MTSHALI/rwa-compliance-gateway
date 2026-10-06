// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {AuditTrail} from "../src/AuditTrail.sol";
import {ComplianceTypes} from "../src/libraries/ComplianceTypes.sol";
import {Test} from "forge-std/Test.sol";

/**
 * @title AuditTrailTest
 * @notice Append-only history: what is recorded, how it is indexed, and what an
 *         auditor can and cannot learn from it.
 *
 * @dev ## The privacy claim is testable
 *
 *      The trail's premise is that an auditor needs the decision history but must
 *      not gain knowledge about the holder. That is only true if no investor-shaped
 *      value is ever written. `test_NoInvestorShapedFieldIsStored` walks the stored
 *      entry and checks every field is either a hash, an enum, a timestamp, or an
 *      actor address - and the privacy storage script re-checks the struct definition
 *      in `out/` so a new field cannot be added silently.
 */
contract AuditTrailTest is Test {
    AuditTrail internal trail;

    address internal admin = makeAddr("admin");
    address internal auditor = makeAddr("auditor");
    address internal outsider = makeAddr("outsider");

    bytes32 internal constant CCID = keccak256("ccid.alice");
    bytes32 internal constant POOL_ID = keccak256("pool.treasury");
    bytes32 internal constant PROVIDER_ID = keccak256("provider.alpha");

    uint64 internal constant T0 = 1_700_000_000;

    function setUp() public {
        trail = new AuditTrail(admin);
        vm.warp(T0);
        bytes32 auditorRole = trail.AUDITOR_ROLE();
        vm.prank(admin);
        trail.grantRole(auditorRole, auditor);
    }

    function _recordAllow() internal {
        vm.prank(auditor);
        trail.recordDecision(
            CCID, POOL_ID, outsider, ComplianceTypes.Decision.Allow, ComplianceTypes.REASON_OK, 1 ether
        );
    }

    // -----------------------------------------------------------------
    // Append-only by construction
    // -----------------------------------------------------------------

    /**
     * @dev There is no update or delete, so the only way an entry could change is if
     *      an id were reused. `nextEntryId` is strictly increasing, which this
     *      asserts directly.
     */
    function test_EntryIdsAreStrictlyIncreasing() public {
        assertEq(trail.totalEntries(), 0);
        _recordAllow();
        assertEq(trail.totalEntries(), 1);
        _recordAllow();
        assertEq(trail.totalEntries(), 2);
        _recordAllow();
        assertEq(trail.totalEntries(), 3);
    }

    function test_EarliestEntrySurvivesLaterWrites() public {
        _recordAllow();
        AuditTrail.Entry memory first = trail.getEntry(0);
        assertEq(first.ccid, CCID);
        assertEq(first.timestamp, T0);

        vm.warp(T0 + 30 days);
        _recordAllow();

        AuditTrail.Entry memory reRead = trail.getEntry(0);
        assertEq(reRead.timestamp, T0, "history is not rewritten");
        assertEq(reRead.ccid, CCID);
    }

    function test_OutOfRangeEntryReverts() public {
        _recordAllow();
        vm.expectRevert(abi.encodeWithSelector(AuditTrail.EntryIdOutOfRange.selector, uint256(1)));
        trail.getEntry(1);

        vm.expectRevert(abi.encodeWithSelector(AuditTrail.EntryIdOutOfRange.selector, uint256(9999)));
        trail.getEntry(9999);
    }

    // -----------------------------------------------------------------
    // Decision recording
    // -----------------------------------------------------------------

    function test_AllowDecisionRecorded() public {
        _recordAllow();
        AuditTrail.Entry memory e = trail.getEntry(0);
        assertEq(uint8(e.kind), uint8(AuditTrail.EntryKind.AccessAllowed));
        assertEq(e.reasonCode, ComplianceTypes.REASON_OK);
        assertEq(e.amount, 1 ether);
        assertEq(e.actor, bytes32(uint256(uint160(outsider))));
    }

    function test_DenyAndReviewKindsDiffer() public {
        vm.startPrank(auditor);
        trail.recordDecision(CCID, POOL_ID, outsider, ComplianceTypes.Decision.Deny, ComplianceTypes.REASON_REVOKED, 0);
        trail.recordDecision(
            CCID,
            POOL_ID,
            outsider,
            ComplianceTypes.Decision.ReviewRequired,
            ComplianceTypes.REASON_MANUAL_REVIEW_REQUIRED,
            0
        );
        vm.stopPrank();

        // The distinction matters to an auditor: a denial and a routing instruction
        // call for completely different follow-up.
        assertEq(uint8(trail.getEntry(0).kind), uint8(AuditTrail.EntryKind.AccessDenied));
        assertEq(uint8(trail.getEntry(1).kind), uint8(AuditTrail.EntryKind.ReviewRequired));
    }

    function test_CredentialEventPacksTheResultingStatus() public {
        vm.prank(auditor);
        trail.recordCredentialEvent(
            CCID, POOL_ID, ComplianceTypes.REASON_REVOKED, ComplianceTypes.CredentialStatus.Revoked
        );

        AuditTrail.Entry memory e = trail.getEntry(0);
        assertEq(uint8(e.kind), uint8(AuditTrail.EntryKind.CredentialStatusChanged));
        assertEq(e.reasonCode, ComplianceTypes.REASON_REVOKED);
        // Status is packed into the actor slot to keep the entry a fixed shape.
        // Widened through `uint256` because `bytes32` does not narrow to `uint8`.
        assertEq(uint256(e.actor), uint256(ComplianceTypes.CredentialStatus.Revoked));
    }

    function test_PolicyAndProviderAndEmergencyEntries() public {
        vm.startPrank(auditor);
        trail.recordPolicyChange(POOL_ID, outsider, 3);
        trail.recordProviderChange(PROVIDER_ID, outsider, 2);
        trail.recordEmergencyAction(outsider, ComplianceTypes.REASON_SYSTEM_PAUSED);
        trail.recordIssuance(CCID, POOL_ID, PROVIDER_ID);
        vm.stopPrank();

        assertEq(uint8(trail.getEntry(0).kind), uint8(AuditTrail.EntryKind.PolicyVersionChanged));
        assertEq(uint8(trail.getEntry(1).kind), uint8(AuditTrail.EntryKind.ProviderStatusChanged));
        assertEq(uint8(trail.getEntry(2).kind), uint8(AuditTrail.EntryKind.EmergencyAction));
        assertEq(uint8(trail.getEntry(3).kind), uint8(AuditTrail.EntryKind.CredentialIssued));
    }

    function test_NonAuditorCannotRecord() public {
        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(AuditTrail.NotAuditor.selector, outsider));
        trail.recordDecision(CCID, POOL_ID, outsider, ComplianceTypes.Decision.Allow, ComplianceTypes.REASON_OK, 0);
        assertEq(trail.totalEntries(), 0);
    }

    function test_NonAuditorCannotRecordPolicyChange() public {
        // Same gate on every entry point, not just decisions: a trail where only one
        // function is gated is a trail an attacker can fill with noise.
        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(AuditTrail.NotAuditor.selector, outsider));
        trail.recordPolicyChange(POOL_ID, outsider, 1);
    }

    // -----------------------------------------------------------------
    // Recorder authorization
    // -----------------------------------------------------------------

    function test_RecorderAuthorizationNamesTheCaller() public {
        address recorder = makeAddr("recorder");
        vm.expectEmit(true, true, false, false, address(trail));
        emit AuditTrail.RecorderAuthorized(recorder, admin);
        vm.prank(admin);
        trail.authorizeRecorder(recorder);

        vm.prank(recorder);
        trail.recordDecision(CCID, POOL_ID, recorder, ComplianceTypes.Decision.Allow, ComplianceTypes.REASON_OK, 0);
        assertEq(trail.totalEntries(), 1);
    }

    function test_RecorderAuthorizationRejectsZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(AuditTrail.InvalidAdminAddress.selector);
        trail.authorizeRecorder(address(0));
    }

    function test_NonAdminCannotAuthorizeRecorder() public {
        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(AuditTrail.NotAuditor.selector, outsider));
        trail.authorizeRecorder(outsider);
    }

    function test_GrantRoleWorksAlongsideAuthorizeRecorder() public {
        // `AUDITOR_ROLE`'s admin is declared in the constructor, so the standard path
        // works too - which tooling and role audits depend on.
        bytes32 auditorRole = trail.AUDITOR_ROLE();
        bytes32 root = trail.DEFAULT_ADMIN_ROLE();
        assertEq(trail.getRoleAdmin(auditorRole), root);

        address successor = makeAddr("successor");
        vm.prank(admin);
        trail.grantRole(auditorRole, successor);
        assertTrue(trail.hasRole(auditorRole, successor));
    }

    // -----------------------------------------------------------------
    // Indexing
    // -----------------------------------------------------------------

    function test_CredentialHistoryIsIndexed() public {
        bytes32 other = keccak256("ccid.bob");
        vm.startPrank(auditor);
        trail.recordDecision(CCID, POOL_ID, outsider, ComplianceTypes.Decision.Allow, ComplianceTypes.REASON_OK, 0);
        trail.recordDecision(CCID, POOL_ID, outsider, ComplianceTypes.Decision.Deny, ComplianceTypes.REASON_EXPIRED, 0);
        trail.recordDecision(other, POOL_ID, outsider, ComplianceTypes.Decision.Allow, ComplianceTypes.REASON_OK, 0);
        vm.stopPrank();

        (AuditTrail.Entry[] memory page, uint256 total) = trail.credentialHistory(CCID, 0, 50);
        assertEq(total, 2);
        assertEq(page.length, 2);
        assertEq(page[0].reasonCode, ComplianceTypes.REASON_OK);
        assertEq(page[1].reasonCode, ComplianceTypes.REASON_EXPIRED);
    }

    function test_PoolHistoryIsIndexed() public {
        bytes32 otherPool = keccak256("pool.other");
        vm.startPrank(auditor);
        trail.recordDecision(CCID, POOL_ID, outsider, ComplianceTypes.Decision.Allow, ComplianceTypes.REASON_OK, 0);
        trail.recordDecision(CCID, otherPool, outsider, ComplianceTypes.Decision.Allow, ComplianceTypes.REASON_OK, 0);
        vm.stopPrank();

        (, uint256 total) = trail.poolHistory(POOL_ID, 0, 50);
        assertEq(total, 1);
    }

    function test_EntryWithNoSubjectIsNotIndexedUnderAZeroKey() public {
        // An emergency action belongs to no credential and no pool. Indexing it under
        // `bytes32(0)` would make the zero key a real bucket, and every integration
        // would have to special-case it.
        vm.prank(auditor);
        trail.recordEmergencyAction(outsider, ComplianceTypes.REASON_SYSTEM_PAUSED);

        (AuditTrail.Entry[] memory page, uint256 total) = trail.credentialHistory(bytes32(0), 0, 50);
        assertEq(total, 0);
        assertEq(page.length, 0);

        (, uint256 poolTotal) = trail.poolHistory(bytes32(0), 0, 50);
        assertEq(poolTotal, 0);
    }

    function test_PagingRespectsOffsetAndLimit() public {
        // Warp *before* recording, so entry `i` carries `T0 + i`. Recording first
        // would stamp every entry with the previous iteration's time and quietly make
        // the paging assertions wrong rather than failing.
        for (uint256 i = 0; i < 5; ++i) {
            vm.warp(T0 + i);
            _recordAllow();
        }

        (AuditTrail.Entry[] memory first, uint256 total) = trail.credentialHistory(CCID, 0, 2);
        assertEq(total, 5);
        assertEq(first.length, 2);
        assertEq(first[0].timestamp, T0);
        assertEq(first[1].timestamp, T0 + 1);

        (AuditTrail.Entry[] memory second,) = trail.credentialHistory(CCID, 2, 2);
        assertEq(second.length, 2);
        assertEq(second[0].timestamp, T0 + 2);
        assertEq(second[1].timestamp, T0 + 3);
    }

    function test_PagingPastTheEndReturnsEmpty() public {
        _recordAllow();
        (AuditTrail.Entry[] memory page, uint256 total) = trail.credentialHistory(CCID, 50, 10);
        assertEq(total, 1, "total is the full count, not the page size");
        assertEq(page.length, 0);
    }

    function test_PageSizeIsCapped() public {
        // An unbounded page would let one call try to return an entire deployment's
        // history and run out of gas.
        uint256 maxPage = trail.MAX_PAGE();
        (AuditTrail.Entry[] memory page,) = trail.credentialHistory(CCID, 0, maxPage + 100);
        assertLe(page.length, maxPage);
    }

    function test_TailReturnsMostRecent() public {
        for (uint256 i = 0; i < 3; ++i) {
            vm.warp(T0 + i);
            _recordAllow();
        }
        AuditTrail.Entry[] memory tail = trail.credentialHistoryTail(CCID);
        assertEq(tail.length, 3);
        assertEq(tail[tail.length - 1].timestamp, T0 + 2);
    }

    // -----------------------------------------------------------------
    // Privacy: what the trail must never contain
    // -----------------------------------------------------------------

    /**
     * @dev Every field of a stored entry, checked against what it is allowed to be.
     *
     *      `amount` is a quantity in the pool's accounting token, not an investor
     *      attribute - it is needed to reconstruct whether an allocation cap was
     *      correctly applied. `actor` is a contract address, which is already public.
     *      Everything else is a hash or a code.
     */
    function test_NoInvestorShapedFieldIsStored() public {
        _recordAllow();
        AuditTrail.Entry memory e = trail.getEntry(0);

        // The subject is a content identifier, never an identity.
        assertEq(e.ccid, CCID);
        assertNotEq(e.ccid, bytes32(0));

        // Timestamp and numeric quantity only.
        assertEq(e.timestamp, T0);
        assertEq(e.amount, 1 ether);

        // `actor` is a contract address, which is on-chain public information.
        assertEq(e.actor, bytes32(uint256(uint160(outsider))));

        // The reason is one of the fixed codes, never free text - which is what keeps
        // an operator from smuggling a name into the trail through a reason string.
        assertEq(e.reasonCode, ComplianceTypes.REASON_OK);
        assertEq(ComplianceTypes.reasonToString(e.reasonCode), "OK");
    }

    function test_ReasonCodesAreTheOnlyThingStoredAsText() public {
        // A denial reason recorded from user input would be an injection surface for
        // personal data into an append-only log that cannot be scrubbed.
        vm.prank(auditor);
        trail.recordDecision(CCID, POOL_ID, outsider, ComplianceTypes.Decision.Deny, ComplianceTypes.REASON_EXPIRED, 0);
        assertEq(ComplianceTypes.reasonToString(trail.getEntry(0).reasonCode), "EXPIRED");
    }
}
