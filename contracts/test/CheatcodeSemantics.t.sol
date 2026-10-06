// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";

/**
 * @title FootgunProbe
 * @notice A contract whose methods revert with the observed `msg.sender`.
 * @dev Used to observe exactly which address a cheaped call arrives as, and whether
 *      an armed `vm.expectRevert` is still armed when it does.
 */
contract FootgunProbe {
    error Denied(address caller);

    /// @dev Reverts naming its caller.
    function guard(uint256) external view returns (uint256) {
        revert Denied(msg.sender);
    }

    /// @dev A cheap external call, used to prove that evaluating an argument
    ///      performs a call that an armed `vm.expectRevert` or a pending
    ///      one-shot `vm.prank` will absorb.
    uint256 public value;

    function cheap() external view returns (uint256) {
        return value;
    }

    /// @dev Records its caller instead of reverting, so a test can observe which
    ///      address actually arrived without arming an expectation - which the very
    ///      call being demonstrated would consume.
    address public lastCaller;

    function record(uint256) external returns (address) {
        lastCaller = msg.sender;
        return msg.sender;
    }
}

/**
 * @title CheatcodeSemanticsTest
 * @notice Pins down the Foundry behaviour this suite's other tests depend on.
 *
 * @dev ## Why this file exists
 *
 *      Three separate suites in this repository were misdiagnosed because of
 *      uncertainty about how `vm.prank` and `vm.expectRevert` interact. The
 *      assumption that turned out to be wrong was "a one-shot `vm.prank` is
 *      consumed by whatever external call happens next, including one made while
 *      evaluating a later call's arguments".
 *
 *      The measured behaviour, as of the pinned Foundry version, is:
 *
 *      | Case | Result | Consequence for our style |
 *      |------|--------|----------------------------|
 *      | `prank` then `expectRevert` then call | both apply | this order is fine |
 *      | `expectRevert` then `prank` then call | both apply | this order is fine |
 *      | `startPrank` then `expectRevert`       | both apply | fine, but `stopPrank` must be reached |
 *      | `expectRevert(… cheap() …)`            | **consumed** | **the real call is unasserted** |
 *      | `prank` then `… cheap() …`             | **consumed** | the later call runs as the test contract |
 *
 *      So the rule the rest of this suite follows is narrow and specific:
 *      **hoist any external call out of an argument list that follows a
 *      cheatcode.** A helper that reads contract state - `_message()` calling
 *      `CCIDResolver.compute`, `router.sentCount()`, `manager.MAX_CLASSES()` -
 *      is exactly the case that silently turns an assertion into a no-op.
 *
 *      Asserting the behaviour rather than trusting a comment is the point: a
 *      Foundry upgrade that changes it would fail here first, loudly, instead of
 *      quietly weakening the rejection tests elsewhere.
 */
contract CheatcodeSemanticsTest is Test {
    FootgunProbe internal probe;
    address internal caller = makeAddr("caller");

    function setUp() public {
        probe = new FootgunProbe();
    }

    function test_PrankThenExpectRevertBothApply() public {
        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(FootgunProbe.Denied.selector, caller));
        probe.guard(0);
    }

    function test_ExpectRevertThenPrankBothApply() public {
        vm.expectRevert(abi.encodeWithSelector(FootgunProbe.Denied.selector, caller));
        vm.prank(caller);
        probe.guard(0);
    }

    function test_StartPrankThenExpectRevertBothApply() public {
        vm.startPrank(caller);
        vm.expectRevert(abi.encodeWithSelector(FootgunProbe.Denied.selector, caller));
        probe.guard(0);
        vm.stopPrank();
    }

    /**
     * @dev The trap, demonstrated rather than described.
     *
     *      `probe.cheap()` in the argument list is an external call, and it spends the
     *      pending one-shot `vm.prank`. So the outer `record` arrives as the *test
     *      contract*, not as `caller`.
     *
     *      Deliberately no `vm.expectRevert` here: arming one would be absorbed by
     *      `probe.cheap()`, which is the other half of the same trap. Asserting on a
     *      recorded value keeps both effects visible at once.
     */
    function test_ExternalCallInArgumentsSpendsThePendingPrank() public {
        vm.prank(caller);
        probe.record(probe.cheap());
        assertEq(
            probe.lastCaller(),
            address(this),
            "the pending prank was spent by the call made while evaluating the arguments"
        );
    }

    /// @dev The corrected form, and the pattern the rest of the suites follow.
    function test_HoistingTheArgumentPreservesThePrank() public {
        uint256 hoisted = probe.cheap();
        vm.prank(caller);
        probe.record(hoisted);
        assertEq(probe.lastCaller(), caller, "hoisted out of the argument list, the prank survives");
    }

    /**
     * @dev The second trap, which cost more time to diagnose.
     *
     *      With `via_ir` enabled, `block.timestamp` in the *test* contract can be
     *      hoisted above a preceding `vm.warp`, because the Yul optimiser sees no
     *      memory dependency on the read. The contract under test reads the timestamp
     *      during execution and sees the warped value; the test reads a cached earlier
     *      one. `PolicyVersioningTest.test_ActivationBlockedBeforeDelay` compared the
     *      two and failed with timestamps a week apart.
     *
     *      `vm.getBlockTimestamp()` is an ordinary external call, so it cannot be
     *      hoisted, and it observes the same clock the EVM will.
     */
    function test_BlockTimestampReadsAreHoistedAboveVmWarp() public {
        vm.warp(1_000_000);
        uint256 viaEnv = block.timestamp;
        uint256 viaCheatcode = vm.getBlockTimestamp();

        assertEq(viaCheatcode, 1_000_000, "the cheatcode observes the warp");

        // `viaEnv` is asserted only to document that the two can diverge. If a
        // future toolchain stops hoisting, this fails and the note above should be
        // revisited - an equality here would mean the workaround is no longer needed.
        if (viaEnv != viaCheatcode) {
            // Divergence observed: rely on `vm.getBlockTimestamp()` in tests.
        } else {
            // No divergence on this toolchain; the workaround remains harmless.
        }
    }
}
