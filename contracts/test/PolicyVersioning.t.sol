// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {PoolPolicyManager} from "../src/PoolPolicyManager.sol";
import {ComplianceTypes} from "../src/libraries/ComplianceTypes.sol";
import {Test} from "forge-std/Test.sol";

/**
 * @title PolicyVersioningTest
 * @notice Registration, the activation delay, supersession, and list semantics.
 *
 * @dev ## Why the delay is the point
 *
 *      Without it, an issuer - or someone holding a compromised issuer key - could
 *      tighten a policy so sharply that every existing investor became instantly
 *      ineligible, with no window in which anyone could notice or respond. Policy
 *      that can change without notice is indistinguishable from arbitrary denial.
 *
 *      So these tests assert the delay as a security property, not a convenience.
 */
contract PolicyVersioningTest is Test {
    PoolPolicyManager internal manager;

    address internal admin = makeAddr("admin");
    address internal outsider = makeAddr("outsider");

    bytes32 internal poolId = keccak256("pool.treasury");
    uint16 internal constant US = 840;

    function setUp() public {
        manager = new PoolPolicyManager(admin);
        vm.warp(1_700_000_000);
    }

    function _registerDefault() internal returns (uint32) {
        vm.prank(admin);
        manager.registerPolicy(
            poolId,
            false,
            new uint16[](0),
            new ComplianceTypes.InvestorClass[](0),
            false,
            0,
            0,
            ComplianceTypes.RevocationMode.IssuerOnly,
            0
        );
        return manager.latestVersion(poolId);
    }

    function _registerJurisdiction(uint16 code) internal {
        uint16[] memory js = new uint16[](1);
        js[0] = code;
        vm.prank(admin);
        manager.registerPolicy(
            poolId,
            false,
            js,
            new ComplianceTypes.InvestorClass[](0),
            false,
            0,
            0,
            ComplianceTypes.RevocationMode.IssuerOnly,
            0
        );
    }

    // -----------------------------------------------------------------
    // Versioning
    // -----------------------------------------------------------------

    function test_VersionsIncrementFromOne() public {
        assertEq(manager.latestVersion(poolId), 0);
        assertEq(_registerDefault(), 1);
        assertEq(_registerDefault(), 2);
        assertEq(_registerDefault(), 3);
    }

    function test_RegistrationDoesNotActivate() public {
        // A registered policy is inert. Otherwise the delay would be meaningless:
        // a misconfigured deployment would already be enforcing it.
        _registerDefault();
        assertFalse(manager.hasActivePolicy(poolId));
        assertTrue(manager.hasAnyPolicy(poolId));
        assertTrue(manager.isPolicyDeactivated(poolId));
        assertEq(manager.activeVersion(poolId), 0);
    }

    function test_PoolWithNoPolicyIsNotDeactivated() public {
        // The distinction the two reason codes rest on: never-configured and
        // switched-off must not look the same.
        assertFalse(manager.hasAnyPolicy(poolId));
        assertFalse(manager.isPolicyDeactivated(poolId));
    }

    function test_RegisteredPolicyIsImmutable() public {
        // A change means a new version. An integrator can pin the version it
        // integrated against and know exactly what it will be evaluated under.
        _registerJurisdiction(US);
        uint32 version = manager.latestVersion(poolId);
        assertTrue(manager.isJurisdictionAccepted(poolId, version, US));
        assertFalse(manager.isJurisdictionAccepted(poolId, version, 826));
    }

    function test_NonAdminCannotRegister() public {
        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(PoolPolicyManager.NotIssuerAdmin.selector, outsider));
        manager.registerPolicy(
            poolId,
            false,
            new uint16[](0),
            new ComplianceTypes.InvestorClass[](0),
            false,
            0,
            0,
            ComplianceTypes.RevocationMode.IssuerOnly,
            0
        );
    }

    function test_ZeroPoolIdRejected() public {
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(PoolPolicyManager.PoolNotRegistered.selector, bytes32(0)));
        manager.registerPolicy(
            bytes32(0),
            false,
            new uint16[](0),
            new ComplianceTypes.InvestorClass[](0),
            false,
            0,
            0,
            ComplianceTypes.RevocationMode.IssuerOnly,
            0
        );
    }

    function test_ListLengthsBounded() public {
        // Bounds are read into locals first. `manager.MAX_JURISDICTIONS()` inside a
        // `vm.expectRevert` argument list is an external call, and it would absorb the
        // armed expectation - so the `registerPolicy` below would revert for an
        // unrelated authorization reason and the assertion would pass vacuously.
        // See CheatcodeSemanticsTest.
        uint256 maxJurisdictions = manager.MAX_JURISDICTIONS();
        uint256 maxClasses = manager.MAX_CLASSES();

        uint16[] memory many = new uint16[](maxJurisdictions + 1);
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(PoolPolicyManager.TooManyJurisdictions.selector, maxJurisdictions + 1));
        manager.registerPolicy(
            poolId,
            false,
            many,
            new ComplianceTypes.InvestorClass[](0),
            false,
            0,
            0,
            ComplianceTypes.RevocationMode.IssuerOnly,
            0
        );

        ComplianceTypes.InvestorClass[] memory classes = new ComplianceTypes.InvestorClass[](maxClasses + 1);
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(PoolPolicyManager.TooManyClasses.selector, maxClasses + 1));
        manager.registerPolicy(
            poolId, false, new uint16[](0), classes, false, 0, 0, ComplianceTypes.RevocationMode.IssuerOnly, 0
        );
    }

    // -----------------------------------------------------------------
    // The activation delay
    // -----------------------------------------------------------------

    function test_ActivationBlockedBeforeDelay() public {
        _registerDefault();
        uint64 activateAfter = uint64(block.timestamp) + manager.POLICY_ACTIVATION_DELAY();

        vm.warp(activateAfter - 1);
        // Read the clock through the cheatcode, not `block.timestamp`.
        //
        // With `via_ir` the optimiser treats `block.timestamp` as having no memory
        // dependency, so a read in the test contract can be hoisted above an earlier
        // `vm.warp`. The contract under test reads the timestamp at execution time
        // and gets the warped value; the test reads a cached one and disagrees. That
        // mismatch is invisible unless the two are compared - which is exactly what
        // this assertion does. See CheatcodeSemanticsTest.
        uint64 observedAt = uint64(vm.getBlockTimestamp());

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(PoolPolicyManager.ActivationDelayNotElapsed.selector, activateAfter, observedAt)
        );
        manager.activatePolicyVersion(poolId, 1);

        assertFalse(manager.hasActivePolicy(poolId), "a policy inside its delay window stays inert");
    }

    function test_ActivationAllowedAtDelay() public {
        _registerDefault();
        uint64 activateAfter = uint64(block.timestamp) + manager.POLICY_ACTIVATION_DELAY();
        vm.warp(activateAfter);

        vm.prank(admin);
        manager.activatePolicyVersion(poolId, 1);
        assertTrue(manager.hasActivePolicy(poolId));
    }

    function test_NonAdminCannotActivate() public {
        _registerDefault();
        vm.warp(block.timestamp + manager.POLICY_ACTIVATION_DELAY());
        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(PoolPolicyManager.NotIssuerAdmin.selector, outsider));
        manager.activatePolicyVersion(poolId, 1);
    }

    function test_ActivatingUnregisteredVersionRejected() public {
        vm.warp(block.timestamp + manager.POLICY_ACTIVATION_DELAY());
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(PoolPolicyManager.PoolNotRegistered.selector, poolId));
        manager.activatePolicyVersion(poolId, 7);
    }

    // -----------------------------------------------------------------
    // Supersession
    // -----------------------------------------------------------------

    function test_ActivationSupersedesThePreviousVersion() public {
        // Exactly one version active per pool. Two would give an integrator an
        // ambiguous answer for the same request.
        _registerJurisdiction(US);
        vm.warp(block.timestamp + manager.POLICY_ACTIVATION_DELAY());
        vm.prank(admin);
        manager.activatePolicyVersion(poolId, 1);

        _registerJurisdiction(826);
        vm.warp(block.timestamp + manager.POLICY_ACTIVATION_DELAY());
        vm.prank(admin);
        manager.activatePolicyVersion(poolId, 2);

        assertEq(manager.activeVersion(poolId), 2);
        assertFalse(manager.getPolicy(poolId, 1).active, "the old version is deactivated");
        assertTrue(manager.getPolicy(poolId, 2).active);
        assertFalse(manager.isJurisdictionAccepted(poolId, 1, 826), "the old version keeps its own list");
        assertTrue(manager.isJurisdictionAccepted(poolId, 2, 826));
    }

    function test_ReactivatingTheSameVersionIsNotASupersession() public {
        _registerDefault();
        vm.warp(block.timestamp + manager.POLICY_ACTIVATION_DELAY());
        vm.startPrank(admin);
        manager.activatePolicyVersion(poolId, 1);
        manager.activatePolicyVersion(poolId, 1);
        vm.stopPrank();
        assertTrue(manager.hasActivePolicy(poolId));
    }

    function test_DeactivationClosesThePoolWithoutReplacingThePolicy() public {
        _registerJurisdiction(US);
        vm.warp(block.timestamp + manager.POLICY_ACTIVATION_DELAY());
        vm.startPrank(admin);
        manager.activatePolicyVersion(poolId, 1);
        manager.deactivateActivePolicy(poolId);
        vm.stopPrank();

        assertFalse(manager.hasActivePolicy(poolId));
        assertTrue(manager.isPolicyDeactivated(poolId));
        // The policy itself stays readable, so a past decision can still be explained.
        assertTrue(manager.isJurisdictionAccepted(poolId, 1, US));
    }

    function test_DeactivationWithNoVersionRejected() public {
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(PoolPolicyManager.NoVersionRegistered.selector, poolId));
        manager.deactivateActivePolicy(poolId);
    }

    // -----------------------------------------------------------------
    // List semantics
    // -----------------------------------------------------------------

    function test_EmptyJurisdictionListMeansAll() public {
        _registerDefault();
        assertTrue(manager.isJurisdictionAccepted(poolId, 1, US));
        assertTrue(manager.isJurisdictionAccepted(poolId, 1, 392));
        assertTrue(manager.isJurisdictionAccepted(poolId, 1, 0));
    }

    function test_JurisdictionListIsAnAllowlist() public {
        _registerJurisdiction(US);
        assertTrue(manager.isJurisdictionAccepted(poolId, 1, US));
        assertFalse(manager.isJurisdictionAccepted(poolId, 1, 826));
    }

    function test_EmptyClassListExcludesBlocked() public {
        // An issuer must opt in to serving blocked investors explicitly. The
        // alternative - an empty list meaning "everything" - would make a denial
        // depend on a pool remembering to configure an exclusion.
        _registerDefault();
        assertTrue(manager.isInvestorClassAccepted(poolId, 1, ComplianceTypes.InvestorClass.USAccredited));
        assertTrue(manager.isInvestorClassAccepted(poolId, 1, ComplianceTypes.InvestorClass.NonUSProfessional));
        assertTrue(manager.isInvestorClassAccepted(poolId, 1, ComplianceTypes.InvestorClass.Unknown));
        assertFalse(manager.isInvestorClassAccepted(poolId, 1, ComplianceTypes.InvestorClass.Blocked));
    }

    function test_BlockedMayBeExplicitlyAccepted() public {
        ComplianceTypes.InvestorClass[] memory classes = new ComplianceTypes.InvestorClass[](1);
        classes[0] = ComplianceTypes.InvestorClass.Blocked;
        vm.prank(admin);
        manager.registerPolicy(
            poolId, false, new uint16[](0), classes, false, 0, 0, ComplianceTypes.RevocationMode.IssuerOnly, 0
        );
        assertTrue(manager.isInvestorClassAccepted(poolId, 1, ComplianceTypes.InvestorClass.Blocked));
        assertFalse(manager.isInvestorClassAccepted(poolId, 1, ComplianceTypes.InvestorClass.USAccredited));
    }

    // -----------------------------------------------------------------
    // Allocation cap
    // -----------------------------------------------------------------

    function test_ZeroCapMeansUncapped() public {
        _registerDefault();
        assertFalse(manager.exceedsAllocationCap(poolId, 1, 0));
        assertFalse(manager.exceedsAllocationCap(poolId, 1, type(uint256).max));
    }

    function test_CapComparisonIsStrictlyAbove() public {
        uint256 cap = 1000;
        ComplianceTypes.InvestorClass[] memory classes = new ComplianceTypes.InvestorClass[](0);
        vm.prank(admin);
        manager.registerPolicy(
            poolId, false, new uint16[](0), classes, false, 0, cap, ComplianceTypes.RevocationMode.IssuerOnly, 0
        );
        assertFalse(manager.exceedsAllocationCap(poolId, 1, cap), "exactly at the cap is allowed");
        assertTrue(manager.exceedsAllocationCap(poolId, 1, cap + 1));
    }

    // -----------------------------------------------------------------
    // Stored fields
    // -----------------------------------------------------------------

    function test_PolicyFieldsRoundTrip() public {
        ComplianceTypes.InvestorClass[] memory classes = new ComplianceTypes.InvestorClass[](2);
        classes[0] = ComplianceTypes.InvestorClass.USAccredited;
        classes[1] = ComplianceTypes.InvestorClass.NonUSProfessional;
        uint16[] memory js = new uint16[](2);
        js[0] = US;
        js[1] = 826;

        vm.prank(admin);
        manager.registerPolicy(
            poolId, true, js, classes, true, 3600, 5 ether, ComplianceTypes.RevocationMode.GovernanceOnly, 0
        );

        ComplianceTypes.PoolPolicy memory p = manager.getPolicy(poolId, 1);
        assertEq(p.poolId, poolId);
        assertEq(p.version, 1);
        assertTrue(p.registered);
        assertFalse(p.active);
        assertTrue(p.requiresManualReview);
        assertTrue(p.requiresFreshReplica);
        assertEq(p.maxReplicaAge, 3600);
        assertEq(p.maxAllocationPerInvestor, 5 ether);
        assertEq(uint8(p.revocationMode), uint8(ComplianceTypes.RevocationMode.GovernanceOnly));
        assertEq(p.acceptedJurisdictions.length, 2);
        assertEq(p.acceptedJurisdictions[1], 826);
        assertEq(p.acceptedInvestorClasses.length, 2);
        assertEq(p.createdAt, uint64(block.timestamp));
    }

    function test_GetActivePolicyIsZeroedWhenNone() public {
        ComplianceTypes.PoolPolicy memory p = manager.getActivePolicy(poolId);
        assertEq(p.poolId, bytes32(0));
        assertEq(p.version, 0);
        assertFalse(p.registered);
    }

    function test_PendingNotificationReportsTheActivationTime() public {
        _registerDefault();
        vm.expectEmit(true, true, true, true, address(manager));
        emit PoolPolicyManager.PolicyPending(poolId, 1, uint64(block.timestamp) + manager.POLICY_ACTIVATION_DELAY());
        vm.prank(admin);
        manager.notifyPending(poolId, 1);
    }

    function test_ZeroAdminRejected() public {
        vm.expectRevert(PoolPolicyManager.InvalidAdminAddress.selector);
        new PoolPolicyManager(address(0));
    }
}
