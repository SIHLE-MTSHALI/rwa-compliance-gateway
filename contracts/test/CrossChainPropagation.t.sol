// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {AuditTrail} from "../src/AuditTrail.sol";
import {CCIDResolver} from "../src/CCIDResolver.sol";
import {ComplianceGateway} from "../src/ComplianceGateway.sol";
import {ComplianceRegistry} from "../src/ComplianceRegistry.sol";
import {CrossChainComplianceReceiver} from "../src/CrossChainComplianceReceiver.sol";
import {CrossChainComplianceSender} from "../src/CrossChainComplianceSender.sol";
import {EmergencyControls} from "../src/EmergencyControls.sol";
import {PoolPolicyManager} from "../src/PoolPolicyManager.sol";
import {ProviderRegistry} from "../src/ProviderRegistry.sol";
import {CompliancePayload} from "../src/libraries/CompliancePayload.sol";
import {ComplianceTypes} from "../src/libraries/ComplianceTypes.sol";
import {ComplianceTestBase} from "./helpers/ComplianceTestBase.sol";
import {MockCCIPRouter} from "./mocks/MockCCIPRouter.sol";

/**
 * @title CrossChainPropagationTest
 * @notice The sender/receiver suite.
 *
 * @dev ## The two regressions this suite exists to prevent
 *
 * 1. **A separate revocation path.** Every state change goes through
 *    {CrossChainComplianceSender.sendCredentialState}, and this suite asserts it
 *    for revoke as well as issue. A sender with an issue-only fast path leaves a
 *    revoked credential looking valid on every destination.
 *
 * 2. **Per-destination deduplication.** There is none. An earlier sibling
 *    implementation skipped destinations a credential had already been sent to,
 *    which meant a revocation could never reach any chain that had already seen
 *    the credential as `Valid` - precisely the chains that mattered. `sentTo` is
 *    retained only as a query, and `test_RevocationReachesEveryDestinationThatSawIssuance`
 *    asserts it is never consulted to skip a send.
 */
contract CrossChainPropagationTest is ComplianceTestBase {
    bytes32 internal poolId = keccak256("pool.treasury");

    // =================================================================
    // Sender
    // =================================================================

    function test_SenderRejectsNonBridgeCaller() public {
        CompliancePayload.Message memory m = _message(SUBJECT, 1, ComplianceTypes.CredentialStatus.Valid);
        uint64[] memory dests = _oneDest();

        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(CrossChainComplianceSender.NotBridge.selector, outsider));
        sourceSenderContract.sendCredentialState(m, dests);
    }

    function test_BridgeBindingIsOneTimeAndPermanent() public {
        // A rebindable sender would let a compromised deployer role redirect
        // credential propagation at any moment - including onto a chain the issuer
        // never intended to reach.
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(CrossChainComplianceSender.BridgeAlreadyInitialized.selector, address(sourceGateway))
        );
        sourceSenderContract.initializeBridge(outsider);

        assertEq(sourceSenderContract.bridge(), address(sourceGateway));
        assertTrue(sourceSenderContract.bridgeInitialized());
    }

    function test_NonAdminCannotBindBridge() public {
        CrossChainComplianceSender fresh =
            new CrossChainComplianceSender(admin, address(router), SOURCE_SELECTOR, sourceEmergency);
        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(CrossChainComplianceSender.NotAdmin.selector, outsider));
        fresh.initializeBridge(outsider);
    }

    function test_UnboundSenderPropagatesNothing() public {
        // An unbound sender must refuse rather than broadcast to whoever calls it.
        CrossChainComplianceSender fresh =
            new CrossChainComplianceSender(admin, address(router), SOURCE_SELECTOR, sourceEmergency);
        CompliancePayload.Message memory m = _message(SUBJECT, 1, ComplianceTypes.CredentialStatus.Valid);
        uint64[] memory dests = _oneDest();

        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(CrossChainComplianceSender.NotBridge.selector, admin));
        fresh.sendCredentialState(m, dests);
    }

    function test_SenderRejectsNonceRegression() public {
        CompliancePayload.Message memory m = _message(SUBJECT, 1, ComplianceTypes.CredentialStatus.Valid);
        uint64[] memory dests = _oneDest();
        vm.prank(address(sourceGateway));
        sourceSenderContract.sendCredentialState(m, dests);

        CompliancePayload.Message memory stale = m;
        stale.nonce = 1;
        vm.prank(address(sourceGateway));
        vm.expectRevert(abi.encodeWithSelector(CrossChainComplianceSender.NonceNotIncreasing.selector, m.ccid, 1, 1));
        sourceSenderContract.sendCredentialState(stale, dests);
    }

    function test_SenderRejectsSelfDestination() public {
        CompliancePayload.Message memory m = _message(SUBJECT, 1, ComplianceTypes.CredentialStatus.Valid);
        uint64[] memory dests = new uint64[](1);
        dests[0] = SOURCE_SELECTOR;

        vm.prank(address(sourceGateway));
        vm.expectRevert(abi.encodeWithSelector(CrossChainComplianceSender.SelfDestination.selector, SOURCE_SELECTOR));
        sourceSenderContract.sendCredentialState(m, dests);
    }

    function test_SenderRejectsEmptyDestinationList() public {
        CompliancePayload.Message memory m = _message(SUBJECT, 1, ComplianceTypes.CredentialStatus.Valid);
        vm.prank(address(sourceGateway));
        vm.expectRevert(CrossChainComplianceSender.NoDestinations.selector);
        sourceSenderContract.sendCredentialState(m, new uint64[](0));
    }

    function test_SenderRejectsTooManyDestinations() public {
        CompliancePayload.Message memory m = _message(SUBJECT, 1, ComplianceTypes.CredentialStatus.Valid);
        uint256 max = sourceSenderContract.MAX_DESTINATIONS();
        uint64[] memory dests = new uint64[](max + 1);
        for (uint256 i = 0; i <= max; ++i) {
            dests[i] = DEST_SELECTOR + uint64(i) + 1;
        }

        vm.prank(address(sourceGateway));
        vm.expectRevert(abi.encodeWithSelector(CrossChainComplianceSender.TooManyDestinations.selector, max + 1));
        sourceSenderContract.sendCredentialState(m, dests);
    }

    function test_SenderRejectsUnknownStatus() public {
        CompliancePayload.Message memory m = _message(SUBJECT, 1, ComplianceTypes.CredentialStatus.Valid);
        m.status = 99;
        vm.prank(address(sourceGateway));
        vm.expectRevert(abi.encodeWithSelector(CrossChainComplianceSender.UnknownStatus.selector, uint8(99)));
        sourceSenderContract.sendCredentialState(m, _oneDest());
    }

    function test_SenderRejectsUnknownClass() public {
        CompliancePayload.Message memory m = _message(SUBJECT, 1, ComplianceTypes.CredentialStatus.Valid);
        m.investorClass = 88;
        vm.prank(address(sourceGateway));
        vm.expectRevert(abi.encodeWithSelector(CrossChainComplianceSender.UnknownClass.selector, uint8(88)));
        sourceSenderContract.sendCredentialState(m, _oneDest());
    }

    function test_SenderRejectsWhileSystemPaused() public {
        vm.prank(guardian);
        sourceEmergency.pause("incident");

        CompliancePayload.Message memory m = _message(SUBJECT, 1, ComplianceTypes.CredentialStatus.Valid);
        vm.prank(address(sourceGateway));
        vm.expectRevert(CrossChainComplianceSender.SystemPaused.selector);
        sourceSenderContract.sendCredentialState(m, _oneDest());
    }

    function test_SenderIsSoleAuthorityOnSourceChainSelector() public {
        // A caller that could choose the source selector could forge messages
        // claiming to originate from another chain. The field is overwritten here.
        CompliancePayload.Message memory m = _message(SUBJECT, 1, ComplianceTypes.CredentialStatus.Valid);
        m.sourceChainSelector = 999;

        vm.prank(address(sourceGateway));
        sourceSenderContract.sendCredentialState(m, _oneDest());

        MockCCIPRouter.SentMessage memory sent = router.sentAt(0);
        (, CompliancePayload.Message memory decoded, CompliancePayload.DecodeError err) = _decode(sent.payload);
        assertEq(uint8(err), uint8(CompliancePayload.DecodeError.None));
        assertEq(decoded.sourceChainSelector, SOURCE_SELECTOR);
    }

    function test_SenderIgnoresSuppliedBindingHashAndRecomputes() public {
        // The sender is the single authority on integrity, so a caller-supplied hash
        // is discarded rather than trusted.
        CompliancePayload.Message memory m = _message(SUBJECT, 1, ComplianceTypes.CredentialStatus.Valid);
        m.bindingHash = keccak256("forged");

        vm.prank(address(sourceGateway));
        sourceSenderContract.sendCredentialState(m, _oneDest());

        MockCCIPRouter.SentMessage memory sent = router.sentAt(0);
        (, CompliancePayload.Message memory decoded, CompliancePayload.DecodeError err) = _decode(sent.payload);
        assertEq(uint8(err), uint8(CompliancePayload.DecodeError.None));
        assertEq(decoded.bindingHash, CompliancePayload.recomputeBindingHash(decoded));
    }

    // =================================================================
    // Receiver: the rejection matrix
    // =================================================================

    function test_ReceiverRejectsDirectCallBypassingRouter() public {
        CompliancePayload.Message memory m = _message(SUBJECT, 1, ComplianceTypes.CredentialStatus.Valid);
        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(CrossChainComplianceReceiver.NotRouter.selector, outsider));
        destReceiver.ccipMessageCallback(
            keccak256("order-x"), address(sourceGateway), destSelector, CompliancePayload.encode(m)
        );
    }

    function test_ReceiverRejectsWrongSelector() public {
        bytes memory payload =
            sourceSenderContract.encodePayload(_message(SUBJECT, 1, ComplianceTypes.CredentialStatus.Valid));
        vm.prank(address(router));
        vm.expectRevert(
            abi.encodeWithSelector(CrossChainComplianceReceiver.UnknownSelector.selector, bytes4(0xdeadbeef))
        );
        destReceiver.ccipMessageCallback(keccak256("order-x"), address(sourceGateway), bytes4(0xdeadbeef), payload);
    }

    function test_ReceiverRejectsUntrustedSourceSender() public {
        bytes memory payload =
            sourceSenderContract.encodePayload(_message(SUBJECT, 1, ComplianceTypes.CredentialStatus.Valid));
        vm.prank(address(router));
        vm.expectRevert(abi.encodeWithSelector(CrossChainComplianceReceiver.UntrustedSourceSender.selector, outsider));
        destReceiver.ccipMessageCallback(keccak256("order-x"), outsider, destSelector, payload);
    }

    function test_ReceiverRejectsUntrustedSourceChain() public {
        // The chain is inside the payload, so it has to be checked there rather than
        // taken from the callback arguments - which the router also supplies, and
        // which a caller cannot be trusted to have cross-checked.
        CompliancePayload.Message memory m = _message(SUBJECT, 1, ComplianceTypes.CredentialStatus.Valid);
        m.sourceChainSelector = 424_242;
        m.bindingHash = CompliancePayload.recomputeBindingHash(m);
        bytes memory payload = CompliancePayload.encode(m);

        vm.prank(address(router));
        vm.expectRevert(
            abi.encodeWithSelector(CrossChainComplianceReceiver.UntrustedSourceChain.selector, uint64(424_242))
        );
        destReceiver.ccipMessageCallback(keccak256("order-x"), address(sourceGateway), destSelector, payload);
    }

    function test_ReceiverRejectsSelfOriginatedChain() public {
        CompliancePayload.Message memory m = _message(SUBJECT, 1, ComplianceTypes.CredentialStatus.Valid);
        m.sourceChainSelector = DEST_SELECTOR;
        m.bindingHash = CompliancePayload.recomputeBindingHash(m);

        vm.prank(address(router));
        vm.expectRevert(
            abi.encodeWithSelector(CrossChainComplianceReceiver.UntrustedSourceChain.selector, DEST_SELECTOR)
        );
        destReceiver.ccipMessageCallback(
            keccak256("order-x"), address(sourceGateway), destSelector, CompliancePayload.encode(m)
        );
    }

    function test_ReceiverRejectsBindingHashMismatch() public {
        // Post-hoc tampering with the payload. The sender committed to these exact
        // contents; recomputing here is what makes an edit detectable.
        //
        // The tampered word is `jurisdictionCode`, chosen deliberately. Tampering the
        // source chain selector instead would be caught by the chain-allowlist check
        // regardless of the binding hash, so a test written that way passes even with
        // the hash verification removed - which is exactly what the mutation harness
        // reported for an earlier version of this test.
        //
        // Nothing else at the receiver re-derives or range-checks a jurisdiction: the
        // destination cannot re-derive the CCID, because that needs the subject
        // commitment the payload deliberately omits. The binding hash is the only
        // defence here, so it is the only thing the assertion can rely on.
        CompliancePayload.Message memory original = _message(SUBJECT, 1, ComplianceTypes.CredentialStatus.Valid);
        bytes memory payload = CompliancePayload.encode(original);

        uint16 tamperedJurisdiction = 392; // Japan, replacing the US
        bytes memory tampered = _withWord(payload, 5, uint256(tamperedJurisdiction));

        // Sanity: the payload really is different, so the test is not vacuous.
        (CompliancePayload.Message memory decoded, CompliancePayload.DecodeError err) =
            CompliancePayload.decode(tampered);
        assertEq(uint8(err), uint8(CompliancePayload.DecodeError.None), "still a structurally valid payload");
        assertEq(decoded.jurisdictionCode, tamperedJurisdiction);
        assertNotEq(
            CompliancePayload.recomputeBindingHash(decoded),
            original.bindingHash,
            "the recomputed hash differs from what the sender signed"
        );

        vm.prank(address(router));
        vm.expectRevert();
        destReceiver.ccipMessageCallback(keccak256("order-x"), address(sourceGateway), destSelector, tampered);

        assertFalse(destRegistry.exists(original.ccid), "nothing was written from a tampered payload");
    }

    /**
     * @dev The same tampering, asserting the *specific* error.
     * @dev Separated from the test above because a bare `vm.expectRevert()` accepts any
     *      revert, which is what let a removed binding-hash check hide behind the chain
     *      allowlist. Naming the error pins the failure to the check that must fire.
     *
     *      `expectPartialRevert` rather than `expectRevert`: the former matches on the
     *      selector alone, while `expectRevert(bytes4)` treats its argument as the
     *      *entire* revert payload - so passing `.selector` there compares the error
     *      against four bytes of selector plus zeroed arguments, and fails for the wrong
     *      reason. The two arguments here are the claimed and recomputed hashes, and
     *      asserting them exactly would mean recomputing the binding in the test, which
     *      is the very duplication that risks drifting from the contract.
     */
    function test_ReceiverRejectsBindingHashMismatchByName() public {
        CompliancePayload.Message memory original = _message(SUBJECT, 1, ComplianceTypes.CredentialStatus.Valid);
        bytes memory payload = CompliancePayload.encode(original);
        bytes memory tampered = _withWord(payload, 5, uint256(uint16(392)));

        vm.prank(address(router));
        vm.expectPartialRevert(CrossChainComplianceReceiver.BindingHashMismatch.selector);
        destReceiver.ccipMessageCallback(keccak256("order-x"), address(sourceGateway), destSelector, tampered);
    }

    function test_ReceiverRejectsReplayedOrderId() public {
        CompliancePayload.Message memory m = _message(SUBJECT, 1, ComplianceTypes.CredentialStatus.Valid);
        bytes memory payload = CompliancePayload.encode(m);
        bytes32 orderId = keccak256("order-replay");

        vm.prank(address(router));
        destReceiver.ccipMessageCallback(orderId, address(sourceGateway), destSelector, payload);

        vm.prank(address(router));
        vm.expectRevert(abi.encodeWithSelector(CrossChainComplianceReceiver.ReplayedMessage.selector, orderId));
        destReceiver.ccipMessageCallback(orderId, address(sourceGateway), destSelector, payload);
    }

    function test_ReceiverRejectsNonceRegression() public {
        CompliancePayload.Message memory first = _message(SUBJECT, 5, ComplianceTypes.CredentialStatus.Valid);
        vm.prank(address(router));
        destReceiver.ccipMessageCallback(
            keccak256("order-a"), address(sourceGateway), destSelector, CompliancePayload.encode(first)
        );

        CompliancePayload.Message memory older = _message(SUBJECT, 4, ComplianceTypes.CredentialStatus.Valid);
        vm.prank(address(router));
        vm.expectRevert(
            abi.encodeWithSelector(CrossChainComplianceReceiver.NonceNotIncreasing.selector, older.ccid, 5, 4)
        );
        destReceiver.ccipMessageCallback(
            keccak256("order-b"), address(sourceGateway), destSelector, CompliancePayload.encode(older)
        );
    }

    function test_ReceiverRejectsWhenProviderNoLongerBacksCredentials() public {
        // Checked per-destination: pausing a provider in one jurisdiction must not
        // depend on propagation from another.
        CompliancePayload.Message memory m = _message(SUBJECT, 1, ComplianceTypes.CredentialStatus.Valid);
        vm.prank(admin);
        destProviders.setProviderStatus(PROVIDER_A, ProviderRegistry.ProviderStatus.Revoked);

        vm.prank(address(router));
        vm.expectRevert(abi.encodeWithSelector(CrossChainComplianceReceiver.ProviderUnavailable.selector, PROVIDER_A));
        destReceiver.ccipMessageCallback(
            keccak256("order-x"), address(sourceGateway), destSelector, CompliancePayload.encode(m)
        );
    }

    function test_ReceiverAcceptsFromDeprecatedProvider() public {
        CompliancePayload.Message memory m = _message(SUBJECT, 1, ComplianceTypes.CredentialStatus.Valid);
        vm.prank(admin);
        destProviders.setProviderStatus(PROVIDER_A, ProviderRegistry.ProviderStatus.Deprecated);

        vm.prank(address(router));
        destReceiver.ccipMessageCallback(
            keccak256("order-x"), address(sourceGateway), destSelector, CompliancePayload.encode(m)
        );
        assertTrue(destRegistry.exists(m.ccid));
    }

    function test_UnwiredReceiverRefusesEverything() public {
        // A receiver that is not a registry writer would silently drop every message.
        // Better to refuse loudly than to accept and write nothing.
        ComplianceRegistry freshRegistry = new ComplianceRegistry(admin);
        ProviderRegistry freshProviders = new ProviderRegistry(admin);
        EmergencyControls freshEmergency = new EmergencyControls(admin, guardian);

        CrossChainComplianceReceiver unwired = new CrossChainComplianceReceiver(
            address(router), DEST_SELECTOR, admin, freshRegistry, freshProviders, freshEmergency
        );
        // A single `startPrank` rather than a `prank` per call: `setAllowedSourceSender`
        // would otherwise spend the one before `registerProvider`, which is the same
        // footgun as the reverse case - a prank covers exactly one external call.
        vm.startPrank(admin);
        unwired.setAllowedSourceSender(address(sourceGateway), true);
        unwired.setAllowedSourceChain(SOURCE_SELECTOR, true);
        _seedProvider(freshProviders, PROVIDER_A);
        vm.stopPrank();
        assertFalse(unwired.wired());

        // Build the payload into a local *before* arming the expectation. Inline,
        // `_message` performs a `CCIDResolver.compute` staticcall while the arguments
        // are evaluated - and that call would consume the pending `expectRevert`,
        // leaving the actual delivery unasserted.
        bytes memory payload = CompliancePayload.encode(_message(SUBJECT, 1, ComplianceTypes.CredentialStatus.Valid));

        vm.startPrank(address(router));
        vm.expectRevert(CrossChainComplianceReceiver.NotWired.selector);
        unwired.ccipMessageCallback(keccak256("order-x"), address(sourceGateway), destSelector, payload);
        vm.stopPrank();
    }

    function test_WireRequiresRegistryWriterRole() public {
        // The failure this guards is invisible until someone notices missing data.
        ComplianceRegistry freshRegistry = new ComplianceRegistry(admin);
        ProviderRegistry freshProviders = new ProviderRegistry(admin);
        EmergencyControls freshEmergency = new EmergencyControls(admin, guardian);
        CrossChainComplianceReceiver receiver = new CrossChainComplianceReceiver(
            address(router), DEST_SELECTOR, admin, freshRegistry, freshProviders, freshEmergency
        );

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(CrossChainComplianceReceiver.NotRegistryWriter.selector, address(receiver))
        );
        receiver.wire();

        // `expectRevert` spent the pending prank, so re-establish it. Each admin-gated
        // call in this block needs its own, since a prank covers one external call.
        vm.prank(admin);
        freshRegistry.setWriter(address(receiver), true);
        vm.prank(admin);
        receiver.wire();
        assertTrue(receiver.wired());

        vm.prank(admin);
        vm.expectRevert(CrossChainComplianceReceiver.AlreadyWired.selector);
        receiver.wire();
    }

    function test_ReceiverRejectsMalformedPayloadLength() public {
        vm.prank(address(router));
        vm.expectRevert(abi.encodeWithSelector(CrossChainComplianceReceiver.MalformedPayload.selector, uint256(32)));
        destReceiver.ccipMessageCallback(
            keccak256("order-x"), address(sourceGateway), destSelector, abi.encode(uint256(1))
        );
    }

    function test_ReceiverRejectsTrailingJunk() public {
        // The exact-length guard is what stops a longer buffer being accepted with
        // a valid prefix and attacker-chosen remainder.
        bytes memory payload =
            sourceSenderContract.encodePayload(_message(SUBJECT, 1, ComplianceTypes.CredentialStatus.Valid));
        bytes memory padded = abi.encodePacked(payload, bytes32(0));

        vm.prank(address(router));
        vm.expectRevert(abi.encodeWithSelector(CrossChainComplianceReceiver.MalformedPayload.selector, uint256(448)));
        destReceiver.ccipMessageCallback(keccak256("order-x"), address(sourceGateway), destSelector, padded);
    }

    function test_ReceiverRejectsUnknownStatus() public {
        bytes memory payload = _withWord(
            sourceSenderContract.encodePayload(_message(SUBJECT, 1, ComplianceTypes.CredentialStatus.Valid)), 9, 42
        );
        vm.prank(address(router));
        vm.expectRevert(abi.encodeWithSelector(CrossChainComplianceReceiver.UnknownStatus.selector, uint8(42)));
        destReceiver.ccipMessageCallback(keccak256("order-x"), address(sourceGateway), destSelector, payload);
    }

    function test_ReceiverRejectsUnknownClass() public {
        bytes memory payload = _withWord(
            sourceSenderContract.encodePayload(_message(SUBJECT, 1, ComplianceTypes.CredentialStatus.Valid)), 10, 77
        );
        vm.prank(address(router));
        vm.expectRevert(abi.encodeWithSelector(CrossChainComplianceReceiver.UnknownClass.selector, uint8(77)));
        destReceiver.ccipMessageCallback(keccak256("order-x"), address(sourceGateway), destSelector, payload);
    }

    function test_ReceiverRejectsNumericOverflow() public {
        // A wide word must not wrap into a small plausible value.
        bytes memory payload = _withWord(
            sourceSenderContract.encodePayload(_message(SUBJECT, 1, ComplianceTypes.CredentialStatus.Valid)),
            4,
            type(uint256).max
        );
        vm.prank(address(router));
        vm.expectRevert(CrossChainComplianceReceiver.NumericOverflow.selector);
        destReceiver.ccipMessageCallback(keccak256("order-x"), address(sourceGateway), destSelector, payload);
    }

    // =================================================================
    // Local authority is never overwritten by a replica
    // =================================================================

    function test_ReplicaCannotOverwriteLocalIssuance() public {
        // The one outcome this whole system exists to make impossible: a compromised
        // source chain restoring `Valid` over a credential this chain is the issuer for.
        address localGateway = _issueLocalOnDestination();
        localGateway; // the gateway address is only needed for the revoke test
        bytes32 localCcid = _localCcid(SUBJECT);

        assertEq(uint8(destRegistry.statusOf(localCcid)), uint8(ComplianceTypes.CredentialStatus.Valid));

        // A remote message for the same CCID must be refused outright.
        CompliancePayload.Message memory m = _message(SUBJECT, 99, ComplianceTypes.CredentialStatus.Valid);
        m.ccid = localCcid;
        m.bindingHash = CompliancePayload.recomputeBindingHash(m);
        bytes memory payload = CompliancePayload.encode(m);

        vm.prank(address(router));
        vm.expectRevert(abi.encodeWithSelector(CrossChainComplianceReceiver.LocalIssuerOverride.selector, localCcid));
        destReceiver.ccipMessageCallback(keccak256("order-x"), address(sourceGateway), destSelector, payload);

        assertEq(
            uint8(destRegistry.statusOf(localCcid)),
            uint8(ComplianceTypes.CredentialStatus.Valid),
            "local state must be untouched by a refused replica"
        );
    }

    function test_ReplicaCannotResurrectLocallyRevokedCredential() public {
        // Stronger than the case above: this chain has already revoked, and the
        // remote message claims `Valid` with a higher nonce. A nonce check alone
        // would not catch this - the remote nonce is higher, so only the
        // local-authority check refuses it.
        address localGateway = _issueLocalOnDestination();
        bytes32 localCcid = _localCcid(SUBJECT);

        vm.prank(localGateway);
        destRegistry.setStatus(localCcid, ComplianceTypes.CredentialStatus.Revoked, bytes32("local-revoke"));
        assertEq(uint8(destRegistry.statusOf(localCcid)), uint8(ComplianceTypes.CredentialStatus.Revoked));

        CompliancePayload.Message memory m = _message(SUBJECT, 500, ComplianceTypes.CredentialStatus.Valid);
        m.ccid = localCcid;
        m.bindingHash = CompliancePayload.recomputeBindingHash(m);
        bytes memory payload = CompliancePayload.encode(m);

        vm.prank(address(router));
        vm.expectRevert(abi.encodeWithSelector(CrossChainComplianceReceiver.LocalIssuerOverride.selector, localCcid));
        destReceiver.ccipMessageCallback(keccak256("order-x"), address(sourceGateway), destSelector, payload);

        assertEq(uint8(destRegistry.statusOf(localCcid)), uint8(ComplianceTypes.CredentialStatus.Revoked));
    }

    // =================================================================
    // The propagation regressions
    // =================================================================

    function test_IssuancePropagatesAndIsRecordedAsReplica() public {
        bytes32 ccid = _issueAndPropagate(1);

        ComplianceTypes.ComplianceCredential memory r = destRegistry.getRecord(ccid);
        assertEq(uint8(r.status), uint8(ComplianceTypes.CredentialStatus.Valid));
        assertEq(r.jurisdictionCode, JURISDICTION_US);
        assertEq(uint8(r.investorClass), uint8(ComplianceTypes.InvestorClass.USAccredited));

        ComplianceTypes.PropagationState memory p = destRegistry.getPropagationState(ccid);
        assertTrue(p.isReplica);
        assertEq(p.sourceChainSelector, SOURCE_SELECTOR);
        assertEq(p.lastSourceNonce, 1);
    }

    function test_RevocationPropagates() public {
        // Regression #1: revocation rides the same path as every other write.
        _seedPermissivePolicy(poolId);
        bytes32 ccid = _issueAndPropagate(1);
        assertTrue(destRegistry.isValid(ccid));

        vm.prank(issuer);
        sourceGateway.revoke(ccid, poolId, bytes32("aml-match"), _oneDest());
        _deliver(router.sentCount() - 1, address(sourceGateway), keccak256("order-revoke"));

        assertEq(uint8(destRegistry.statusOf(ccid)), uint8(ComplianceTypes.CredentialStatus.Revoked));
        assertFalse(destRegistry.isValid(ccid));
    }

    function test_RevocationReachesEveryDestinationThatSawIssuance() public {
        // Regression #2: no per-destination dedup. `sentTo` is a query, never a
        // skip-list. An earlier sibling skipped destinations that already had the
        // credential, which made revocation impossible exactly where it mattered.
        _seedPermissivePolicy(poolId);

        uint64[] memory twoDests = new uint64[](2);
        twoDests[0] = DEST_SELECTOR;
        twoDests[1] = 16_015_286_601_757_825_754;

        ComplianceTypes.CredentialResult memory r = _defaultResult(SUBJECT, 1);
        r.destinationChainSelectors = twoDests;

        vm.prank(workflow);
        sourceGateway.submitCredentialResult(r);

        assertTrue(sourceSenderContract.hasSentTo(r.ccid, DEST_SELECTOR));
        assertTrue(sourceSenderContract.hasSentTo(r.ccid, 16_015_286_601_757_825_754));

        // Revoke to the *same* set. If any destination were skipped because it had
        // already seen the credential, these two counts would diverge.
        uint256 sentBefore = router.sentCount();
        vm.prank(issuer);
        sourceGateway.revoke(r.ccid, poolId, bytes32("aml"), twoDests);
        assertEq(router.sentCount(), sentBefore + 2, "revocation must reach both destinations");
    }

    function test_SuspendAndResumePropagate() public {
        bytes32 ccid = _issueAndPropagate(1);

        vm.prank(issuer);
        sourceGateway.suspend(ccid, bytes32("under-review"), _oneDest());
        _deliver(router.sentCount() - 1, address(sourceGateway), keccak256("order-suspend"));
        assertEq(uint8(destRegistry.statusOf(ccid)), uint8(ComplianceTypes.CredentialStatus.Suspended));

        vm.prank(issuer);
        sourceGateway.resume(ccid, bytes32("cleared"), _oneDest());
        _deliver(router.sentCount() - 1, address(sourceGateway), keccak256("order-resume"));
        assertEq(uint8(destRegistry.statusOf(ccid)), uint8(ComplianceTypes.CredentialStatus.Valid));
    }

    function test_RenewalPropagates() public {
        bytes32 ccid = _issueAndPropagate(1);

        vm.warp(block.timestamp + 10 days);
        ComplianceTypes.CredentialResult memory r = _defaultResult(SUBJECT, 2);
        vm.prank(workflow);
        sourceGateway.renewCredential(r, _oneDest(), uint64(block.timestamp) + TTL, 2);
        _deliver(router.sentCount() - 1, address(sourceGateway), keccak256("order-renew"));

        ComplianceTypes.ComplianceCredential memory stored = destRegistry.getRecord(ccid);
        assertEq(stored.nonce, 2);
        assertEq(stored.expiresAt, uint64(block.timestamp) + TTL);
    }

    function test_StatusChangeIsRejectedWhileDestinationPaused() public {
        _seedPermissivePolicy(poolId);
        bytes32 ccid = _issueAndPropagate(1);

        vm.prank(guardian);
        destEmergency.pause("destination incident");

        // Source-side write succeeds; the destination refuses the message.
        vm.prank(issuer);
        sourceGateway.revoke(ccid, poolId, bytes32("aml"), _oneDest());

        // Read the recorded message into locals first. Evaluating these inside the
        // `expectRevert` argument list would spend the expectation on the router
        // calls that succeed, and the real revert would then go unasserted.
        MockCCIPRouter.SentMessage memory sent = router.sentAt(router.sentCount() - 1);

        vm.prank(address(router));
        vm.expectRevert(CrossChainComplianceReceiver.SystemPaused.selector);
        destReceiver.ccipMessageCallback(sent.messageId, address(sourceGateway), destSelector, sent.payload);
    }

    function test_FailedDeliveryLeavesOrderIdRetryable() public {
        // Rejections revert, so a message refused for a fixable reason (a paused
        // system) can be redelivered once the cause is resolved. Marking it consumed
        // before the checks would burn it permanently.
        CompliancePayload.Message memory m = _message(SUBJECT, 1, ComplianceTypes.CredentialStatus.Valid);
        bytes memory payload = CompliancePayload.encode(m);
        bytes32 orderId = keccak256("order-retryable");

        vm.prank(address(router));
        destReceiver.ccipMessageCallback(orderId, address(sourceGateway), destSelector, payload);
        assertTrue(destReceiver.consumedOrderIds(orderId));
    }

    /**
     * @dev A revocation must carry a nonce the destination will accept.
     *
     *      This is the property that makes cross-chain revocation work at all, and it
     *      is not observable from a single chain: the destination discards any message
     *      whose nonce does not exceed what it already holds.
     *
     *      So if {ComplianceRegistry.setStatus} stopped bumping the nonce, a revocation
     *      would carry the *issuance's* nonce, every destination would reject it as
     *      stale, and a revoked credential would remain valid everywhere it had already
     *      propagated - with the source chain correctly reporting `Revoked`.
     *
     *      Asserted against the destination's own accepted-nonce bookkeeping, which is
     *      the thing that would actually refuse the message.
     */
    function test_RevocationCarriesANonceTheDestinationWillAccept() public {
        bytes32 ccid = _issueAndPropagate(1);
        assertEq(destReceiver.lastAcceptedNonce(ccid), 1, "issuance propagated with nonce 1");

        // The registry must have advanced its nonce on the status change, not just
        // changed the status.
        uint64 afterIssuance = sourceRegistry.getRecord(ccid).nonce;
        assertEq(afterIssuance, 1);

        vm.prank(issuer);
        sourceGateway.revoke(ccid, bytes32(0), bytes32("aml"), _oneDest());

        uint64 afterRevocation = sourceRegistry.getRecord(ccid).nonce;
        assertGt(afterRevocation, afterIssuance, "a status change must advance the nonce");

        // And the destination, which enforces strict increase, must accept it.
        _deliver(router.sentCount() - 1, address(sourceGateway), keccak256("order-nonce"));
        assertEq(destReceiver.lastAcceptedNonce(ccid), afterRevocation);
        assertEq(uint8(destRegistry.statusOf(ccid)), uint8(ComplianceTypes.CredentialStatus.Revoked));
    }

    /**
     * @dev The same property for a suspension, which is the common case rather than the
     *      rare one - a suspension that no destination accepts is a suspension that
     *      does not exist off the source chain.
     */
    function test_SuspensionCarriesANonceTheDestinationWillAccept() public {
        bytes32 ccid = _issueAndPropagate(1);
        uint64 issued = sourceRegistry.getRecord(ccid).nonce;

        vm.prank(issuer);
        sourceGateway.suspend(ccid, bytes32("review"), _oneDest());
        uint64 suspended = sourceRegistry.getRecord(ccid).nonce;
        assertGt(suspended, issued, "suspension must advance the nonce");

        _deliver(router.sentCount() - 1, address(sourceGateway), keccak256("order-suspend-nonce"));
        assertEq(destReceiver.lastAcceptedNonce(ccid), suspended);
    }

    // =================================================================
    // Helpers
    // =================================================================

    function _oneDest() internal pure returns (uint64[] memory d) {
        d = new uint64[](1);
        d[0] = DEST_SELECTOR;
    }

    /**
     * @dev A message as the sender would emit it, including its binding hash.
     *
     *      Tests that bypass {CrossChainComplianceSender} still have to produce a
     *      valid commitment, because the receiver checks it before anything else -
     *      an unsigned message would fail the integrity check rather than the one
     *      under test, and the assertion would pass for the wrong reason.
     */
    function _message(bytes32 subjectCommitment, uint64 nonce, ComplianceTypes.CredentialStatus status)
        internal
        view
        returns (CompliancePayload.Message memory m)
    {
        m.ccid = sourceResolver.compute(
            CRED_TYPE,
            SCHEMA_VERSION,
            PROVIDER_A,
            JURISDICTION_US,
            ComplianceTypes.InvestorClass.USAccredited,
            subjectCommitment
        );
        m.credentialType = CRED_TYPE;
        m.providerId = PROVIDER_A;
        m.evidenceHash = EVIDENCE;
        m.schemaVersion = SCHEMA_VERSION;
        m.jurisdictionCode = JURISDICTION_US;
        m.investorClass = uint8(ComplianceTypes.InvestorClass.USAccredited);
        m.issuedAt = uint64(block.timestamp);
        m.expiresAt = uint64(block.timestamp) + TTL;
        m.nonce = nonce;
        m.status = uint8(status);
        m.sourceChainSelector = SOURCE_SELECTOR;
        m.bindingHash = CompliancePayload.recomputeBindingHash(m);
    }

    function _issueAndPropagate(uint64 nonce) internal returns (bytes32 ccid) {
        ComplianceTypes.CredentialResult memory r = _defaultResult(SUBJECT, nonce);
        r.destinationChainSelectors = _oneDest();

        uint256 before = router.sentCount();
        vm.prank(workflow);
        sourceGateway.submitCredentialResult(r);
        ccid = r.ccid;
        _deliver(before, address(sourceGateway), keccak256("order-issue"));
    }

    /**
     * @dev Deploy a gateway that is the local issuer for the *destination* chain,
     *      writing into {destRegistry}. Returns the gateway's address, which is the
     *      only writer for that registry besides the receiver.
     *
     *      It reuses `destRegistry` and `destProviders` rather than deploying fresh
     *      ones, because the point is that the receiver under test sees a credential
     *      it is authoritative for. A gateway wired to its own registry would write
     *      elsewhere and the scenario would silently not be exercised.
     */
    function _issueLocalOnDestination() internal returns (address localGateway) {
        PoolPolicyManager policies = new PoolPolicyManager(admin);
        AuditTrail audit = new AuditTrail(admin);
        EmergencyControls emergency = new EmergencyControls(admin, guardian);
        CrossChainComplianceSender sender =
            new CrossChainComplianceSender(admin, address(router), DEST_SELECTOR, emergency);
        ComplianceGateway gateway = new ComplianceGateway(
            admin, destRegistry, destProviders, policies, sourceResolver, audit, sender, emergency
        );
        localGateway = address(gateway);

        // One `startPrank` for the whole wiring block, starting with the bridge
        // binding: a per-call `prank` is easy to get wrong when an earlier
        // admin-gated call quietly consumes one.
        vm.startPrank(admin);
        sender.initializeBridge(localGateway);
        destRegistry.setWriter(localGateway, true);
        audit.authorizeRecorder(localGateway);
        gateway.grantRole(gateway.WORKFLOW_SUBMITTER(), workflow);
        vm.stopPrank();

        ComplianceTypes.CredentialResult memory r = _defaultResult(SUBJECT, 1);
        vm.prank(workflow);
        gateway.submitCredentialResult(r);
    }

    function _localCcid(bytes32 subjectCommitment) internal view returns (bytes32) {
        return sourceResolver.compute(
            CRED_TYPE,
            SCHEMA_VERSION,
            PROVIDER_A,
            JURISDICTION_US,
            ComplianceTypes.InvestorClass.USAccredited,
            subjectCommitment
        );
    }

    function _decode(bytes memory data)
        internal
        pure
        returns (uint256 schemaVersion, CompliancePayload.Message memory m, CompliancePayload.DecodeError err)
    {
        (m, err) = CompliancePayload.decode(data);
        schemaVersion = m.schemaVersion;
    }

    /**
     * @dev Overwrite one 32-byte word of a payload, for tamper tests.
     *
     *      Field order, as encoded by `CompliancePayload.encode`:
     *
     *      ```
     *      0 ccid              5 jurisdictionCode   10 investorClass
     *      1 credentialType    6 issuedAt           11 sourceChainSelector
     *      2 providerId        7 expiresAt          12 bindingHash
     *      3 evidenceHash      8 nonce
     *      4 schemaVersion     9 status
     *      ```
     *
     *      `data` is a memory pointer to the length word, so the first payload word
     *      is at `data + 0x20` - one step, not two.
     */
    function _withWord(bytes memory data, uint256 index, uint256 value) internal pure returns (bytes memory out) {
        out = data;
        assembly {
            mstore(add(add(out, 0x20), mul(index, 0x20)), value)
        }
    }
}
