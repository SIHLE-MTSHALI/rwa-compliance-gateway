// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ComplianceRegistry} from "./ComplianceRegistry.sol";
import {EmergencyControls} from "./EmergencyControls.sol";
import {ProviderRegistry} from "./ProviderRegistry.sol";
import {ICCIPReceiver} from "./interfaces/ICCIP.sol";
import {CompliancePayload} from "./libraries/CompliancePayload.sol";
import {ComplianceTypes} from "./libraries/ComplianceTypes.sol";

/**
 * @title CrossChainComplianceReceiver
 * @notice Accepts compliance state propagated from a trusted source chain and
 *         records it as a local replica.
 *
 * @dev ## A replica is a cache, not an authority
 *
 *      This chain verified nothing; it trusted a message from a configured peer.
 *      Two consequences follow, and both are enforced:
 *
 *      - Freshness is recorded ({ComplianceRegistry.getPropagationState}), so a
 *        pool can refuse a replica older than it tolerates.
 *      - A replica can never improve local state. If this chain is itself the
 *        issuer for a CCID, an inbound message is rejected. Without that check a
 *        compromised source chain could overwrite a locally revoked credential with
 *        `Valid` - the one outcome this system exists to make impossible.
 *
 * @dev ## Validation, one attack per check
 *
 *      | Check                    | Attack it stops                             |
 *      |--------------------------|---------------------------------------------|
 *      | `msg.sender == ROUTER`   | direct calls bypassing CCIP                |
 *      | pause check              | writes during an incident                  |
 *      | selector match           | wrong receiver function / misrouted call   |
 *      | `ALLOWED_SOURCE_SENDERS` | any address forging a payload              |
 *      | `ALLOWED_SOURCE_CHAINS`  | message replayed from an unexpected chain  |
 *      | payload length + ranges  | malformed / truncated input                 |
 *      | `bindingHash`            | a message altered after the sender signed it |
 *      | local-issuer check       | remote state overwriting local authority   |
 *      | provider backs creds    | reliance on a compromised provider         |
 *      | increasing nonce         | out-of-order and replayed state            |
 *
 * @dev ## Fail closed
 *
 *      Rejections revert, which in CCIP v2 marks the message failed rather than
 *      silently dropping it. An unhandled inbound message is an operational signal
 *      this system would rather surface loudly.
 *
 * @dev ## There is exactly one entry point
 *
 *      `ccipMessageCallback` is the only external function that reaches {_accept}. An
 *      earlier version also exposed a public `receiveMessage`, documented as a testability
 *      surface - and it was a hole: it skipped the `msg.sender == ROUTER` check and took
 *      `sender` as a caller-supplied argument. Anyone could therefore call it with an
 *      allowlisted sender address and a payload whose binding hash they had computed
 *      themselves (`computeBindingHash` is public), injecting arbitrary replicas of
 *      arbitrary credentials while the receiver recorded the trusted sender.
 *
 *      Nothing used it: the test suites drive the real callback through a mock router or
 *      `vm.prank(address(ROUTER))`, so the tests were not what justified it either. Tests
 *      must impersonate the router, exactly as an attacker would have to.
 */
contract CrossChainComplianceReceiver is ICCIPReceiver {
    using ComplianceTypes for bytes32;

    /// @notice The authorized CCIP router. The only caller permitted to deliver.
    address public immutable ROUTER;

    /// @notice This chain's own selector, used to reject self-addressed messages.
    uint64 public immutable DESTINATION_CHAIN_SELECTOR;

    ComplianceRegistry public immutable REGISTRY;
    ProviderRegistry public immutable PROVIDERS;
    EmergencyControls public immutable EMERGENCY;

    /// @notice Administrators allowed to configure trusted sources.
    address public immutable ADMIN;

    /// @notice Source-chain senders whose messages are honoured.
    mapping(address => bool) public ALLOWED_SOURCE_SENDERS;

    /// @notice Source chain selectors whose messages are honoured.
    mapping(uint64 => bool) public ALLOWED_SOURCE_CHAINS;

    /**
     * @notice True once {wire} has confirmed this contract can write.
     * @dev A receiver that is not a registry writer would silently drop every
     *      propagation. Rather than discover that from missing data, it refuses to
     *      accept anything until wiring is verified.
     */
    bool public wired;

    event CredentialReplicaAccepted(
        bytes32 indexed ccid,
        bytes32 indexed credentialType,
        uint64 indexed sourceChainSelector,
        address sourceSender,
        uint64 nonce,
        uint8 status
    );
    event CredentialReplicaRejected(bytes32 indexed ccid, uint64 indexed nonce, string reason);
    event ReceiverWired(address indexed receiver);

    /// @dev orderId => consumed. Replay defence.
    mapping(bytes32 => bool) public consumedOrderIds;

    /// @dev ccid => highest nonce accepted.
    mapping(bytes32 => uint64) public lastAcceptedNonce;

    error NotRouter(address caller);
    error NotAdmin(address caller);
    error SystemPaused();
    error UnknownSelector(bytes4 receivedSelector);
    error ReplayedMessage(bytes32 orderId);
    error UntrustedSourceSender(address sender);
    error UntrustedSourceChain(uint64 sourceChainSelector);
    error MalformedPayload(uint256 length);
    error UnknownStatus(uint8 status);
    error UnknownClass(uint8 cls);
    error NumericOverflow();
    error ProviderUnavailable(bytes32 providerId);
    error NonceNotIncreasing(bytes32 ccid, uint64 current, uint64 submitted);
    error LocalIssuerOverride(bytes32 ccid);
    error BindingHashMismatch(bytes32 claimed, bytes32 recomputed);
    error NotRegistryWriter(address account);
    error NotWired();
    error AlreadyWired();
    error ZeroAddress();

    constructor(
        address router,
        uint64 destinationChainSelector,
        address admin,
        ComplianceRegistry registry,
        ProviderRegistry providers,
        EmergencyControls emergency
    ) {
        if (router == address(0) || admin == address(0)) revert ZeroAddress();
        ROUTER = router;
        DESTINATION_CHAIN_SELECTOR = destinationChainSelector;
        ADMIN = admin;
        REGISTRY = registry;
        PROVIDERS = providers;
        EMERGENCY = emergency;
        // The writer role cannot be verified here: this contract's own address does
        // not exist until after the constructor returns. {wire} does it.
    }

    /**
     * @notice Confirm this contract holds the registry writer role, then arm.
     * @dev Must be called once, by the admin, after the registry has authorized
     *      this receiver. Until then every inbound message is refused with
     *      {NotWired}.
     *
     *      A deployment that skipped this would otherwise accept messages and write
     *      nothing - the worst possible failure mode, because it looks healthy while
     *      silently losing credential state.
     */
    function wire() external {
        if (msg.sender != ADMIN) revert NotAdmin(msg.sender);
        if (wired) revert AlreadyWired();
        if (!REGISTRY.isWriter(address(this))) revert NotRegistryWriter(address(this));
        wired = true;
        emit ReceiverWired(address(this));
    }

    modifier onlyAdmin() {
        if (msg.sender != ADMIN) revert NotAdmin(msg.sender);
        _;
    }

    function setAllowedSourceSender(address sender, bool allowed) external onlyAdmin {
        if (sender == address(0)) revert ZeroAddress();
        ALLOWED_SOURCE_SENDERS[sender] = allowed;
    }

    function setAllowedSourceChain(uint64 chainSelector, bool allowed) external onlyAdmin {
        ALLOWED_SOURCE_CHAINS[chainSelector] = allowed;
    }

    /// @notice The receiver function the router dispatches to.
    function selector() external pure returns (bytes4) {
        return CrossChainComplianceReceiver.receiveCredential.selector;
    }

    /**
     * @notice CCIP entry point, called by the router on delivery.
     */
    function ccipMessageCallback(bytes32 orderId, address sender, bytes4 receivedSelector, bytes calldata data)
        external
        returns (bytes4)
    {
        if (msg.sender != ROUTER) revert NotRouter(msg.sender);
        if (EMERGENCY.isPaused()) revert SystemPaused();
        if (receivedSelector != CrossChainComplianceReceiver.receiveCredential.selector) {
            emit CredentialReplicaRejected(bytes32(0), 0, "UNKNOWN_SELECTOR");
            revert UnknownSelector(receivedSelector);
        }
        if (!ALLOWED_SOURCE_SENDERS[sender]) {
            emit CredentialReplicaRejected(bytes32(0), 0, "UNTRUSTED_SOURCE_SENDER");
            revert UntrustedSourceSender(sender);
        }

        (CompliancePayload.Message memory m, CompliancePayload.DecodeError err) = CompliancePayload.decode(data);

        // Each branch reverts directly rather than via a helper returning `error`:
        // Solidity's `revert` takes a constructor call, not a function result.
        // Distinguishing the cases matters - `MalformedPayload` suggests a version
        // mismatch, `UnknownStatus` suggests a sender bug, and operators act on
        // those differently.
        if (err == CompliancePayload.DecodeError.UnknownStatus) {
            emit CredentialReplicaRejected(bytes32(0), 0, "UNKNOWN_STATUS");
            revert UnknownStatus(_rawWord(data, 9));
        }
        if (err == CompliancePayload.DecodeError.UnknownClass) {
            emit CredentialReplicaRejected(bytes32(0), 0, "UNKNOWN_CLASS");
            revert UnknownClass(_rawWord(data, 10));
        }
        if (err == CompliancePayload.DecodeError.NumericOverflow) {
            emit CredentialReplicaRejected(bytes32(0), 0, "NUMERIC_OVERFLOW");
            revert NumericOverflow();
        }
        if (err != CompliancePayload.DecodeError.None) {
            emit CredentialReplicaRejected(bytes32(0), 0, "MALFORMED_PAYLOAD");
            revert MalformedPayload(data.length);
        }

        _accept(orderId, sender, m);
        return ICCIPReceiver.ccipMessageCallback.selector;
    }

    /**
     * @notice Target function for CCIP dispatch. Not called directly.
     * @dev Exists so {selector} has something stable to name. All enforcement lives in
     *      {ccipMessageCallback}, which is the only path into {_accept}.
     */
    function receiveCredential() external pure {
        // Intentionally empty. Reaching this function through a router does nothing;
        // `ccipMessageCallback` inspects `msg.sender` and `receivedSelector` itself.
    }

    // ---------------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------------

    function _accept(bytes32 orderId, address sender, CompliancePayload.Message memory m) private {
        if (!wired) revert NotWired();

        if (consumedOrderIds[orderId]) {
            emit CredentialReplicaRejected(m.ccid, m.nonce, "REPLAYED_MESSAGE");
            revert ReplayedMessage(orderId);
        }
        if (!ALLOWED_SOURCE_CHAINS[m.sourceChainSelector]) {
            emit CredentialReplicaRejected(m.ccid, m.nonce, "UNTRUSTED_SOURCE_CHAIN");
            revert UntrustedSourceChain(m.sourceChainSelector);
        }
        if (m.sourceChainSelector == DESTINATION_CHAIN_SELECTOR) {
            emit CredentialReplicaRejected(m.ccid, m.nonce, "SELF_SOURCE_CHAIN");
            revert UntrustedSourceChain(m.sourceChainSelector);
        }

        // Integrity: the sender committed to these exact contents. Recomputing here
        // is what makes a post-hoc edit to the payload detectable.
        bytes32 recomputed = CompliancePayload.recomputeBindingHash(m);
        if (recomputed != m.bindingHash) {
            emit CredentialReplicaRejected(m.ccid, m.nonce, "BINDING_HASH_MISMATCH");
            revert BindingHashMismatch(m.bindingHash, recomputed);
        }

        // A replica must never overwrite state this chain is authoritative for.
        // Checked before any write, so a refused override costs nothing.
        if (REGISTRY.exists(m.ccid) && !REGISTRY.getPropagationState(m.ccid).isReplica) {
            emit CredentialReplicaRejected(m.ccid, m.nonce, "LOCAL_ISSUER_OVERRIDE");
            revert LocalIssuerOverride(m.ccid);
        }

        // A paused or revoked provider must not have its attestations trusted on
        // this chain either. Checked per-destination, so pausing a provider in one
        // jurisdiction does not depend on propagation from another.
        if (!PROVIDERS.backsExistingCredentials(m.providerId)) {
            emit CredentialReplicaRejected(m.ccid, m.nonce, "PROVIDER_UNAVAILABLE");
            revert ProviderUnavailable(m.providerId);
        }

        uint64 current = lastAcceptedNonce[m.ccid];
        if (m.nonce <= current) {
            emit CredentialReplicaRejected(m.ccid, m.nonce, "STALE_NONCE");
            revert NonceNotIncreasing(m.ccid, current, m.nonce);
        }

        // Consumed markers are written last. If any check above reverts the whole
        // transaction reverts, leaving the order id unconsumed so the message can be
        // retried once an operator has fixed the underlying cause, rather than being
        // burned permanently.
        consumedOrderIds[orderId] = true;
        lastAcceptedNonce[m.ccid] = m.nonce;

        REGISTRY.applyReplica(
            m.ccid,
            m.credentialType,
            m.providerId,
            m.evidenceHash,
            m.schemaVersion,
            m.jurisdictionCode,
            ComplianceTypes.InvestorClass(m.investorClass),
            m.issuedAt,
            m.expiresAt,
            m.nonce,
            ComplianceTypes.CredentialStatus(m.status),
            m.sourceChainSelector
        );

        emit CredentialReplicaAccepted(m.ccid, m.credentialType, m.sourceChainSelector, sender, m.nonce, m.status);
    }

    /**
     * @dev Read one 32-byte word from a length-checked payload, purely to name it in
     *      an error. Field index 9 is `status`, 10 is `investorClass`.
     */
    function _rawWord(bytes memory data, uint256 index) private pure returns (uint8 raw) {
        assembly {
            // data points at the length word; the payload starts 32 bytes in.
            raw := byte(31, mload(add(add(data, 0x20), mul(index, 0x20))))
        }
    }
}
