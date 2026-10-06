// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {EmergencyControls} from "./EmergencyControls.sol";
import {ICCIPRouter} from "./interfaces/ICCIP.sol";
import {CompliancePayload} from "./libraries/CompliancePayload.sol";
import {ComplianceTypes} from "./libraries/ComplianceTypes.sol";

/**
 * @title CrossChainComplianceSender
 * @notice Encodes and dispatches compliance credential state over CCIP.
 *
 * @dev ## The deployment cycle
 *
 *      The sender must know its gateway, and the gateway must hold the sender, so
 *      the two cannot both take the other as a constructor argument. The sender is
 *      therefore deployed first and bound once via {initializeBridge}.
 *
 *      That is safe because the binding is one-way and permanent: `bridge` starts
 *      unset, only the deployer may set it, and only once. An unbound sender
 *      propagates nothing rather than propagating to the wrong caller.
 *
 * @dev ## Every state change propagates
 *
 *      Issue, renew, suspend, resume, expire, and revoke all go through
 *      {sendCredentialState}. There is no separate fast path for revocation, because
 *      a channel that only sometimes exists is precisely how a revoked credential
 *      ends up still looking valid somewhere.
 *
 *      **No per-destination deduplication.** An earlier version of the sibling
 *      `identity-bridge-zktls` sender skipped destinations it had already sent to,
 *      which silently made revocation impossible for any chain that had already seen
 *      a credential as `Valid`. Replay defence belongs on the receiver, which
 *      requires a strictly increasing nonce.
 */
contract CrossChainComplianceSender {
    /// @notice The deployer. May perform the one-time bridge binding and nothing else.
    address public immutable ADMIN;

    /// @notice The CCIP router.
    ICCIPRouter public immutable ROUTER;

    /// @notice This chain's CCIP selector, embedded in every payload.
    uint64 public immutable SOURCE_CHAIN_SELECTOR;

    EmergencyControls public immutable EMERGENCY;

    /// @notice The gateway authorized to dispatch. Zero until {initializeBridge}.
    address public bridge;

    /// @notice True once {bridge} has been set.
    bool public bridgeInitialized;

    event CredentialSent(
        bytes32 indexed ccid,
        bytes32 indexed credentialType,
        uint64 indexed destinationChainSelector,
        uint64 nonce,
        bytes32 ccipMessageId,
        uint8 status
    );
    event BridgeInitialized(address indexed bridge);

    /// @dev ccid => highest nonce dispatched.
    mapping(bytes32 => uint64) public lastSentNonce;

    /// @dev ccid => destination => true once ever dispatched.
    mapping(bytes32 => mapping(uint64 => bool)) public sentTo;

    error NotBridge(address caller);
    error NotAdmin(address caller);
    error BridgeAlreadyInitialized(address existing);
    error SystemPaused();
    error NoDestinations();
    error TooManyDestinations(uint256 length);
    error SelfDestination(uint64 destinationChainSelector);
    error NonceNotIncreasing(bytes32 ccid, uint64 current, uint64 submitted);
    error UnknownStatus(uint8 status);
    error UnknownClass(uint8 cls);
    error RouterNotConfigured();

    /// @dev Bounded per call so one result cannot exceed block gas.
    uint256 public constant MAX_DESTINATIONS = 10;

    constructor(address admin, address router, uint64 sourceChainSelector, EmergencyControls emergency) {
        if (admin == address(0) || router == address(0)) revert RouterNotConfigured();
        ADMIN = admin;
        ROUTER = ICCIPRouter(router);
        SOURCE_CHAIN_SELECTOR = sourceChainSelector;
        EMERGENCY = emergency;
    }

    /**
     * @notice Bind this sender to its gateway. Callable exactly once, by the deployer.
     * @dev Breaks the gateway/sender constructor cycle. Permanent by design: a
     *      rebindable sender would let a compromised deployer role redirect
     *      credential propagation at any moment.
     */
    function initializeBridge(address bridge_) external {
        if (msg.sender != ADMIN) revert NotAdmin(msg.sender);
        if (bridgeInitialized) revert BridgeAlreadyInitialized(bridge);
        if (bridge_ == address(0)) revert RouterNotConfigured();
        bridge = bridge_;
        bridgeInitialized = true;
        emit BridgeInitialized(bridge_);
    }

    /**
     * @notice Propagate credential state to the given destinations.
     * @dev The gateway calls this after any state change. Revocation included.
     * @param m Credential state. `bindingHash` is ignored on input and recomputed
     *        here, so the sender is the single authority on it.
     */
    function sendCredentialState(CompliancePayload.Message memory m, uint64[] calldata destinations)
        external
        returns (uint256 sentCount)
    {
        if (msg.sender != bridge) revert NotBridge(msg.sender);
        if (EMERGENCY.isPaused()) revert SystemPaused();
        if (destinations.length == 0) revert NoDestinations();
        if (destinations.length > MAX_DESTINATIONS) revert TooManyDestinations(destinations.length);
        if (m.nonce <= lastSentNonce[m.ccid]) revert NonceNotIncreasing(m.ccid, lastSentNonce[m.ccid], m.nonce);

        if (uint256(m.status) > uint256(ComplianceTypes.CredentialStatus.Revoked)) revert UnknownStatus(m.status);
        if (uint256(m.investorClass) > uint256(ComplianceTypes.InvestorClass.Blocked)) {
            revert UnknownClass(m.investorClass);
        }

        for (uint256 i = 0; i < destinations.length; ++i) {
            if (destinations[i] == SOURCE_CHAIN_SELECTOR) revert SelfDestination(destinations[i]);
        }

        // This contract is the sole authority on the source chain selector. The
        // caller does not supply it - a caller that could would be able to forge
        // messages claiming to originate from another chain.
        m.sourceChainSelector = SOURCE_CHAIN_SELECTOR;
        m.bindingHash = CompliancePayload.recomputeBindingHash(m);
        bytes memory payload = CompliancePayload.encode(m);

        // Recorded before dispatch: a partially failed batch must not be retryable
        // with the same nonce, or a destination could be skipped silently while the
        // retry appears to succeed.
        lastSentNonce[m.ccid] = m.nonce;

        for (uint256 i = 0; i < destinations.length; ++i) {
            uint64 dest = destinations[i];
            bytes32 messageId = ROUTER.send(
                ICCIPRouter.EVM2AnyMessage({
                    receiver: abi.encode(address(this)), data: payload, destChainSelector: dest
                })
            );
            sentTo[m.ccid][dest] = true;
            emit CredentialSent(m.ccid, m.credentialType, dest, m.nonce, messageId, m.status);
            ++sentCount;
        }
    }

    /// @notice Highest nonce dispatched for a credential.
    function getLastSentNonce(bytes32 ccid) external view returns (uint64) {
        return lastSentNonce[ccid];
    }

    /// @notice Whether a credential has ever been dispatched to a destination.
    function hasSentTo(bytes32 ccid, uint64 destinationChainSelector) external view returns (bool) {
        return sentTo[ccid][destinationChainSelector];
    }

    /// @notice The payload this sender would emit, for tests and off-chain tooling.
    function encodePayload(CompliancePayload.Message memory m) external view returns (bytes memory) {
        m.sourceChainSelector = SOURCE_CHAIN_SELECTOR;
        m.bindingHash = CompliancePayload.recomputeBindingHash(m);
        return CompliancePayload.encode(m);
    }
}
