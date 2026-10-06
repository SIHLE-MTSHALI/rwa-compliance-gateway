// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {EmergencyControls} from "../src/EmergencyControls.sol";
import {Test} from "forge-std/Test.sol";

/**
 * @title EmergencyControlsTest
 * @notice The pause / unpause flow.
 *
 * @dev ## The asymmetry is the security property
 *
 *      Pausing is instant and single-call. Resuming is two-step with a mandatory
 *      delay, and the guardian who can pause cannot resume.
 *
 *      The reason is directional: stopping is cheap and reversible, so it should be
 *      immediate. Resuming is the risky direction, and it is exactly when the
 *      pressure to resume is highest - during an unresolved incident. A delay gives
 *      that pressure somewhere to land other than the pause itself.
 *
 *      If a future refactor makes these symmetric, these tests fail.
 */
contract EmergencyControlsTest is Test {
    EmergencyControls internal emergency;

    address internal admin = makeAddr("admin");
    address internal guardian = makeAddr("guardian");
    address internal outsider = makeAddr("outsider");

    function setUp() public {
        emergency = new EmergencyControls(admin, guardian);
        vm.warp(1_700_000_000);
    }

    // -----------------------------------------------------------------
    // Roles
    // -----------------------------------------------------------------

    function test_InitialRoles() public {
        assertTrue(emergency.hasRole(emergency.GUARDIAN(), guardian));
        assertTrue(emergency.hasRole(emergency.TIMELOCK_ADMIN(), admin));
        assertFalse(emergency.hasRole(emergency.GUARDIAN(), admin));
        assertFalse(emergency.paused());
    }

    function test_GuardianKeyIsHandoverable() public {
        // Declared role admins in the constructor. Without them `grantRole` resolves
        // the admin to `bytes32(0)`, so a guardian could never be rotated - and an
        // incident would be handled by whichever address happened to be in the
        // constructor, which is not a runbook anyone can rely on.
        //
        // Keys hoisted: `emergency.GUARDIAN()` is an external call and would spend
        // the pending prank. See CheatcodeSemanticsTest.
        bytes32 guardianRole = emergency.GUARDIAN();
        bytes32 timelockRole = emergency.TIMELOCK_ADMIN();
        bytes32 root = emergency.DEFAULT_ADMIN_ROLE();

        assertEq(emergency.getRoleAdmin(guardianRole), root);
        assertEq(emergency.getRoleAdmin(timelockRole), root);

        address successor = makeAddr("successor-guardian");
        vm.prank(admin);
        emergency.grantRole(guardianRole, successor);
        assertTrue(emergency.hasRole(guardianRole, successor));
    }

    function test_ZeroConstructorAddressesRejected() public {
        vm.expectRevert(EmergencyControls.InvalidAddress.selector);
        new EmergencyControls(address(0), guardian);
        vm.expectRevert(EmergencyControls.InvalidAddress.selector);
        new EmergencyControls(admin, address(0));
    }

    // -----------------------------------------------------------------
    // Pause
    // -----------------------------------------------------------------

    function test_GuardianCanPauseImmediately() public {
        vm.prank(guardian);
        emergency.pause("oracle compromise");

        assertTrue(emergency.isPaused());
        assertEq(emergency.unpauseExecutableAt(), 0, "no unpause is implied by a pause");
    }

    function test_NonGuardianCannotPause() public {
        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(EmergencyControls.NotGuardian.selector, outsider));
        emergency.pause("nope");
        assertFalse(emergency.isPaused());
    }

    function test_AdminIsNotImplicitlyAGuardian() public {
        // Pause authority is deliberately narrow: it is the one role that can act
        // without waiting, so it should not come with the rest of admin rights.
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(EmergencyControls.NotGuardian.selector, admin));
        emergency.pause("nope");
    }

    function test_DoublePauseRejected() public {
        vm.startPrank(guardian);
        emergency.pause("first");
        vm.expectRevert(EmergencyControls.AlreadyPaused.selector);
        emergency.pause("second");
        vm.stopPrank();
    }

    function test_PauseReasonLengthBounded() public {
        uint256 maxLength = emergency.MAX_REASON_LENGTH();
        bytes memory long = new bytes(maxLength + 1);
        vm.prank(guardian);
        vm.expectRevert(abi.encodeWithSelector(EmergencyControls.ReasonTooLong.selector, maxLength + 1));
        emergency.pause(string(long));
    }

    // -----------------------------------------------------------------
    // Unpause: two steps, and the guardian cannot start either
    // -----------------------------------------------------------------

    function test_GuardianCannotResume() public {
        // The asymmetry. A guardian who can pause in one transaction must not be able
        // to undo it in one, or the delay buys nothing.
        vm.prank(guardian);
        emergency.pause("incident");

        vm.prank(guardian);
        vm.expectRevert(abi.encodeWithSelector(EmergencyControls.NotTimelockAdmin.selector, guardian));
        emergency.scheduleUnpause("resolved");

        // ...nor can it cancel a scheduled unpause.
        vm.startPrank(admin);
        emergency.scheduleUnpause("resolved");
        vm.stopPrank();
        vm.prank(guardian);
        vm.expectRevert(abi.encodeWithSelector(EmergencyControls.NotTimelockAdmin.selector, guardian));
        emergency.cancelUnpause();
    }

    function test_ResumingWhileNotPausedRejected() public {
        vm.startPrank(admin);
        vm.expectRevert(EmergencyControls.NotPaused.selector);
        emergency.scheduleUnpause("nope");
        vm.expectRevert(EmergencyControls.NotPaused.selector);
        emergency.executeUnpause();
        vm.stopPrank();
    }

    function test_UnpauseRequiresSchedulingFirst() public {
        vm.prank(guardian);
        emergency.pause("incident");
        vm.prank(admin);
        vm.expectRevert(EmergencyControls.UnpauseNotScheduled.selector);
        emergency.executeUnpause();
    }

    function test_SchedulingDoesNotUnpause() public {
        // The delay is a delay, not a formality: scheduling must leave the system
        // paused until `executeUnpause` runs.
        vm.prank(guardian);
        emergency.pause("incident");
        vm.prank(admin);
        emergency.scheduleUnpause("resolved");

        assertTrue(emergency.isPaused(), "still paused after scheduling");
        assertEq(emergency.unpauseExecutableAt(), 1_700_000_000 + emergency.UNPAUSE_DELAY());
    }

    function test_ExecuteBlockedUntilDelayElapses() public {
        vm.prank(guardian);
        emergency.pause("incident");
        vm.prank(admin);
        emergency.scheduleUnpause("resolved");

        uint64 executableAt = emergency.unpauseExecutableAt();
        vm.warp(executableAt - 1);
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(EmergencyControls.UnpauseDelayNotElapsed.selector, executableAt, executableAt - 1)
        );
        emergency.executeUnpause();
        assertTrue(emergency.isPaused());
    }

    function test_ExecuteAtDelayElapses() public {
        vm.prank(guardian);
        emergency.pause("incident");
        vm.prank(admin);
        emergency.scheduleUnpause("resolved");

        uint64 executableAt = emergency.unpauseExecutableAt();
        vm.warp(executableAt);
        vm.prank(admin);
        emergency.executeUnpause();

        assertFalse(emergency.isPaused());
        assertEq(emergency.unpauseExecutableAt(), 0, "the schedule is consumed");
    }

    function test_AnyoneMayExecuteOnceEligible() public {
        // Execution is permissionless on purpose. The consent is already given: a
        // timelock admin scheduled this and the delay has passed. If only that admin
        // could execute, a lost or rotated key would leave the system paused
        // indefinitely - the worst outcome an emergency control can produce.
        //
        // The safety valve is cancellation, not a restricted execute.
        vm.prank(guardian);
        emergency.pause("incident");
        vm.prank(admin);
        emergency.scheduleUnpause("resolved");

        uint64 executableAt = emergency.unpauseExecutableAt();
        vm.warp(executableAt);
        vm.prank(outsider);
        emergency.executeUnpause();
        assertFalse(emergency.isPaused());
    }

    function test_CancelUnpauseKeepsTheSystemPaused() public {
        vm.prank(guardian);
        emergency.pause("incident");
        vm.startPrank(admin);
        emergency.scheduleUnpause("resolved");
        emergency.cancelUnpause();
        vm.stopPrank();

        assertTrue(emergency.isPaused(), "cancelling must not resume anything");
        assertEq(emergency.unpauseExecutableAt(), 0);

        vm.warp(block.timestamp + 30 days);
        vm.prank(admin);
        vm.expectRevert(EmergencyControls.UnpauseNotScheduled.selector);
        emergency.executeUnpause();
    }

    /**
     * @dev The operator procedure for an incident that recurs inside the unpause
     *      window, and the reason {EmergencyControls.pause} does not clear a pending
     *      unpause itself: the system is still paused, so `pause` rejects it. Cancel
     *      is the only action available - and it is enough.
     */
    function test_RecurringIncidentIsHandledByCancelling() public {
        vm.startPrank(guardian);
        emergency.pause("first incident");
        vm.stopPrank();

        vm.startPrank(admin);
        emergency.scheduleUnpause("believed resolved");
        vm.stopPrank();

        // Incident recurs. The system is already paused, so there is nothing to pause;
        // the pending unpause is what has to be withdrawn.
        vm.startPrank(admin);
        emergency.cancelUnpause();
        vm.stopPrank();

        assertTrue(emergency.isPaused());
        assertEq(emergency.unpauseExecutableAt(), 0);

        vm.warp(block.timestamp + 365 days);
        // Permissionless execute does not mean unconditional execute: with no window
        // scheduled there is nothing to execute, and the call still refuses.
        vm.expectRevert(EmergencyControls.UnpauseNotScheduled.selector);
        emergency.executeUnpause();
        assertTrue(emergency.isPaused(), "still paused a year later, with no window scheduled");
    }

    function test_ReschedulingResetsTheDelay() public {
        // Re-scheduling must push the executable time out again, not keep the earlier
        // (possibly much closer) one - otherwise a cancelled-then-rescheduled unpause
        // could execute immediately.
        vm.startPrank(guardian);
        emergency.pause("incident");
        vm.stopPrank();

        vm.startPrank(admin);
        emergency.scheduleUnpause("first");
        uint64 firstExecutable = emergency.unpauseExecutableAt();

        vm.warp(firstExecutable - 1 hours);
        emergency.scheduleUnpause("second");
        assertEq(emergency.unpauseExecutableAt(), firstExecutable - 1 hours + emergency.UNPAUSE_DELAY());
        assertGt(emergency.unpauseExecutableAt(), firstExecutable);
        vm.stopPrank();
    }

    function test_NonTimelockAdminCannotCancel() public {
        vm.prank(guardian);
        emergency.pause("incident");
        vm.startPrank(admin);
        emergency.scheduleUnpause("resolved");
        vm.stopPrank();

        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(EmergencyControls.NotTimelockAdmin.selector, outsider));
        emergency.cancelUnpause();
    }
}
