// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/**
 * @title ICCIPRouter
 * @notice Minimal, faithful subset of the Chainlink CCIP v2 router interface.
 *
 * @dev ## Why these are declared locally instead of vendored
 *
 *      The production system calls the real Chainlink CCIP router. This repository
 *      declares the subset it depends on rather than vendoring the upstream
 *      `chainlink-contracts` package, for two reasons:
 *
 *      1. A reviewer should be able to `forge build` with `forge-std` alone. A
 *         vendored dependency tree makes the build depend on network access and
 *         pins the repo to one upstream release.
 *      2. The security-relevant surface is three declarations. Keeping it in-repo
 *         means the thing an auditor reads is the thing that runs.
 *
 *      Signatures match CCIP v2 exactly, so swapping in the real router is a
 *      deployment-time address change.
 */
interface ICCIPRouter {
    /// @notice A message from an EVM chain to any chain. Field order is protocol-defined.
    struct EVM2AnyMessage {
        bytes receiver; // abi-encoded receiver address on the destination
        bytes data; // abi-encoded payload for the destination receiver
        uint64 destChainSelector; // CCIP chain selector of the destination
    }

    /// @notice Send a message. Returns the CCIP message id.
    function send(EVM2AnyMessage calldata message) external returns (bytes32 messageId);
}

/**
 * @title ICCIPReceiver
 * @notice Minimal, faithful subset of the Chainlink CCIP receiver interface.
 * @dev `ccipMessageCallback` is called by the router only, and must validate
 *      `msg.sender` before trusting any field in the payload.
 */
interface ICCIPReceiver {
    /**
     * @notice Callback invoked by the CCIP router on delivery.
     * @param orderId Unique message id; used here as a replay key.
     * @param sender The source-chain sender address as reported by CCIP.
     * @param receivedSelector The receiver function selector CCIP is invoking.
     * @param data The abi-encoded payload.
     */
    function ccipMessageCallback(bytes32 orderId, address sender, bytes4 receivedSelector, bytes calldata data)
        external
        returns (bytes4);
}
