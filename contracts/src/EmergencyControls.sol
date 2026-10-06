// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title EmergencyControls
 * @notice System-wide pause with a reason, consulted by every write and access path.
 *
 * @dev ## Fail closed
 *
 *      While paused, {PoolComplianceModule.evaluate} returns
 *      `SYSTEM_PAUSED` and `Deny`. This is the safe direction: if the system cannot
 *      tell whether its own state is trustworthy, it must not report that an
 *      investor is compliant.
 *
 *      A pause does not hide existing state. Registry and policy reads stay
 *      available so holders, integrators, and auditors keep seeing what is true
 *      right now. A pause stops new decisions; it does not rewrite history.
 *
 * @dev ## Asymmetric pause and resume
 *
 *      `GUARDIAN` pauses immediately, no delay. `TIMELOCK_ADMIN` resumes through a
 *      two-step flow with a mandatory delay.
 *
 *      The asymmetry is intentional. Stopping is cheap and reversible, so it should
 *      be instant. Resuming is the risky direction, and it is exactly when pressure
 *      to resume is highest - during an unresolved incident. Making resume slow
 *      gives that pressure somewhere to land other than the pause itself.
 */
contract EmergencyControls is AccessControl {
    /// @dev May pause immediately. May not resume.
    bytes32 public constant GUARDIAN = keccak256("GUARDIAN");

    /// @dev May schedule and execute an unpause.
    bytes32 public constant TIMELOCK_ADMIN = keccak256("TIMELOCK_ADMIN");

    /// @notice True while the system is paused.
    bool public paused;

    /// @notice Earliest timestamp a scheduled unpause may execute.
    uint64 public unpauseExecutableAt;

    /// @notice Delay between scheduling and executing an unpause.
    uint64 public constant UNPAUSE_DELAY = 24 hours;

    /// @notice Max reason length, so events stay cheap and bounded.
    uint256 public constant MAX_REASON_LENGTH = 256;

    event PauseStateChanged(bool paused, string reason);
    event UnpauseScheduled(uint64 executableAt, string reason);
    event UnpauseExecuted();
    event UnpauseCancelled();

    error NotGuardian(address caller);
    error NotTimelockAdmin(address caller);
    error InvalidAddress();
    error AlreadyPaused();
    error NotPaused();
    error UnpauseNotScheduled();
    error UnpauseDelayNotElapsed(uint64 executableAt, uint64 nowTs);
    error ReasonTooLong(uint256 length);

    constructor(address admin, address guardian) {
        if (admin == address(0) || guardian == address(0)) revert InvalidAddress();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(GUARDIAN, guardian);
        _grantRole(TIMELOCK_ADMIN, admin);

        // Declared so the roles are grantable at all. `AccessControl.grantRole`
        // resolves a role's admin to `bytes32(0)` by default, which no account can
        // hold - so without these lines a guardian or timelock key could never be
        // rotated, and an incident would have to be handled by whichever address
        // happened to be in the constructor.
        _setRoleAdmin(GUARDIAN, DEFAULT_ADMIN_ROLE);
        _setRoleAdmin(TIMELOCK_ADMIN, DEFAULT_ADMIN_ROLE);
    }

    function isPaused() external view returns (bool) {
        return paused;
    }

    /**
     * @notice Pause the system. Immediate, single call, no delay.
     * @dev Does **not** clear a pending unpause, because that would be unreachable:
     *      an unpause can only be scheduled while paused, and `pause` rejects an
     *      already-paused system. The operator procedure for an incident that recurs
     *      inside the delay window is {cancelUnpause}, which does clear it.
     *
     * @param reason Short human-readable cause, emitted for responders. Must not
     *        contain investor data; it is public chain state.
     */
    function pause(string calldata reason) external {
        if (!hasRole(GUARDIAN, msg.sender)) revert NotGuardian(msg.sender);
        if (paused) revert AlreadyPaused();
        if (bytes(reason).length > MAX_REASON_LENGTH) revert ReasonTooLong(bytes(reason).length);
        paused = true;
        emit PauseStateChanged(true, reason);
    }

    /**
     * @notice Schedule an unpause. Executes no earlier than {UNPAUSE_DELAY} later.
     * @dev Two steps, so resuming is always a deliberate, public, delayed act.
     *
     *      Emits only {UnpauseScheduled} and **not** `PauseStateChanged(false, ...)`.
     *      An earlier version emitted both, which made the log claim the system was live
     *      the moment a window was opened - a full {UNPAUSE_DELAY} early. A monitor
     *      alerting on `PauseStateChanged` would have reported the system healthy while
     *      every access check still returned `SYSTEM_PAUSED`. The state only changes when
     *      {executeUnpause} runs, so the state event belongs there alone.
     */
    function scheduleUnpause(string calldata reason) external {
        if (!hasRole(TIMELOCK_ADMIN, msg.sender)) revert NotTimelockAdmin(msg.sender);
        if (!paused) revert NotPaused();
        if (bytes(reason).length > MAX_REASON_LENGTH) revert ReasonTooLong(bytes(reason).length);
        unpauseExecutableAt = uint64(block.timestamp) + UNPAUSE_DELAY;
        emit UnpauseScheduled(unpauseExecutableAt, reason);
    }

    /**
     * @notice Execute a scheduled unpause once the delay has elapsed.
     * @dev Permissionless on purpose. The consent is already given: a `TIMELOCK_ADMIN`
     *      scheduled this, and the delay has passed. Requiring the same key a second
     *      time adds no safety and creates a real failure mode - a lost or rotated
     *      timelock key would leave the system paused indefinitely, which is the worst
     *      outcome an emergency control can produce.
     *
     *      The safety valve is {cancelUnpause}: whoever scheduled the unpause can
     *      withdraw it at any point before execution, so an open execute never
     *      outruns the operator's intent.
     */
    function executeUnpause() external {
        if (!paused) revert NotPaused();
        if (unpauseExecutableAt == 0) revert UnpauseNotScheduled();
        if (uint64(block.timestamp) < unpauseExecutableAt) {
            revert UnpauseDelayNotElapsed(unpauseExecutableAt, uint64(block.timestamp));
        }
        paused = false;
        unpauseExecutableAt = 0;
        emit UnpauseExecuted();
        emit PauseStateChanged(false, "");
    }

    /// @notice Cancel a scheduled unpause. Does not unpause.
    function cancelUnpause() external {
        if (!hasRole(TIMELOCK_ADMIN, msg.sender)) revert NotTimelockAdmin(msg.sender);
        if (!paused) revert NotPaused();
        unpauseExecutableAt = 0;
        emit UnpauseCancelled();
        emit PauseStateChanged(true, "unpause cancelled");
    }
}
