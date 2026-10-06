// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ICCIPRouter} from "../../src/interfaces/ICCIP.sol";
import {ICCIPReceiver} from "../../src/interfaces/ICCIP.sol";

/**
 * @title MockCCIPRouter
 * @notice Test double for the Chainlink CCIP router. Records outbound messages and
 *         can deliver them to a receiver on demand.
 *
 * @dev ## Why this exists
 *
 *      The real router is asynchronous, off-chain, and needs a funded LINK balance.
 *      Testing against it would mean integration tests that cannot run in CI. This
 *      mock keeps the two properties the receiver actually depends on:
 *
 *      1. `send` returns a message id and the caller is `msg.sender`.
 *      2. Delivery invokes `ccipMessageCallback` with `msg.sender == router`.
 *
 *      Everything the receiver validates - router identity, source sender, selector,
 *      order id, payload bytes - is therefore exercised for real. What is *not*
 *      exercised is the real router's own guarantees, which is why
 *      `docs/threat-model.md` treats the router as a trusted external dependency.
 *
 *      `deliver` and `deliverRaw` are deliberately permissionless in test code so a
 *      test can impersonate a misbehaving source chain.
 */
contract MockCCIPRouter is ICCIPRouter {
    struct SentMessage {
        address from;
        address to;
        uint64 destChainSelector;
        bytes payload;
        bytes32 messageId;
    }

    SentMessage[] internal _sent;

    event MessageSent(bytes32 indexed messageId, address indexed from, uint64 indexed destChainSelector, bytes payload);
    event MessageDelivered(bytes32 indexed orderId, address indexed receiver, address sourceSender);

    error NoSuchMessage(uint256 index);
    error DeliveryFailed(bytes reason);

    function send(EVM2AnyMessage calldata message) external returns (bytes32 messageId) {
        // Deterministic and collision-free per (sender, destination, payload,
        // sequence), so a test can assert on a specific id.
        messageId = keccak256(abi.encode(msg.sender, message.destChainSelector, message.data, _sent.length));
        _sent.push(
            SentMessage({
                from: msg.sender,
                to: abi.decode(message.receiver, (address)),
                destChainSelector: message.destChainSelector,
                payload: message.data,
                messageId: messageId
            })
        );
        emit MessageSent(messageId, msg.sender, message.destChainSelector, message.data);
    }

    function sentCount() external view returns (uint256) {
        return _sent.length;
    }

    function sentAt(uint256 index) external view returns (SentMessage memory) {
        if (index >= _sent.length) revert NoSuchMessage(index);
        return _sent[index];
    }

    /// @notice The address a recorded message is addressed to.
    function receiverOf(uint256 index) external view returns (address) {
        if (index >= _sent.length) revert NoSuchMessage(index);
        return _sent[index].to;
    }

    /**
     * @notice Deliver a recorded message to its destination receiver.
     * @param index Index into the recorded messages.
     * @param receiver Destination receiver contract.
     * @param sourceSender Address the router would report as the sender on the
     *        source chain. Supplied by the test so spoofing can be simulated.
     * @param orderId CCIP message id. Supplied by the test so replay can be simulated.
     * @param receivedSelector Receiver function selector.
     */
    function deliver(uint256 index, address receiver, address sourceSender, bytes32 orderId, bytes4 receivedSelector)
        external
    {
        if (index >= _sent.length) revert NoSuchMessage(index);
        _invoke(receiver, sourceSender, orderId, receivedSelector, _sent[index].payload);
    }

    /// @notice Deliver arbitrary bytes as if the router had received them.
    /// @dev Used for malformed-payload tests, which no recorded message can produce.
    function deliverRaw(
        address receiver,
        address sourceSender,
        bytes32 orderId,
        bytes4 receivedSelector,
        bytes memory data
    ) external {
        _invoke(receiver, sourceSender, orderId, receivedSelector, data);
    }

    /**
     * @dev Calls the receiver and bubbles up its revert verbatim.
     *
     *      The receiver's own named error is what a test needs to assert - that a
     *      replay produced `ReplayedMessage` rather than something generic. Wrapping
     *      the revert here would hide exactly the information the tests exist to
     *      check, so the raw returndata is re-thrown as-is.
     */
    function _invoke(
        address receiver,
        address sourceSender,
        bytes32 orderId,
        bytes4 receivedSelector,
        bytes memory data
    ) private {
        (bool ok, bytes memory ret) = receiver.call(
            abi.encodeWithSelector(
                ICCIPReceiver.ccipMessageCallback.selector, orderId, sourceSender, receivedSelector, data
            )
        );
        if (!ok) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }
        if (abi.decode(ret, (bytes4)) != ICCIPReceiver.ccipMessageCallback.selector) {
            revert DeliveryFailed("bad selector returned");
        }
        emit MessageDelivered(orderId, receiver, sourceSender);
    }
}
