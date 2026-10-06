// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";

import {AuditTrail} from "../../src/AuditTrail.sol";
import {CCIDResolver} from "../../src/CCIDResolver.sol";
import {ComplianceGateway} from "../../src/ComplianceGateway.sol";
import {ComplianceRegistry} from "../../src/ComplianceRegistry.sol";
import {CrossChainComplianceReceiver} from "../../src/CrossChainComplianceReceiver.sol";
import {CrossChainComplianceSender} from "../../src/CrossChainComplianceSender.sol";
import {EmergencyControls} from "../../src/EmergencyControls.sol";
import {PoolComplianceModule} from "../../src/PoolComplianceModule.sol";
import {PoolPolicyManager} from "../../src/PoolPolicyManager.sol";
import {ProviderRegistry} from "../../src/ProviderRegistry.sol";
import {ComplianceTypes} from "../../src/libraries/ComplianceTypes.sol";
import {MockCCIPRouter} from "../mocks/MockCCIPRouter.sol";

/**
 * @title ComplianceTestBase
 * @notice Shared fixture deploying the full system twice - as an issuing chain and
 *         as a destination chain - plus helpers for issuing and asserting.
 *
 * @dev ## Why two deployments
 *
 *      Source and destination share a router address but have separate registries,
 *      which is what makes the replica rules testable: `dest` has no local issuer,
 *      so anything it holds is genuinely a replica.
 */
abstract contract ComplianceTestBase is Test {
    // ---------------------------------------------------------------------
    // Actors
    // ---------------------------------------------------------------------
    address internal admin = makeAddr("admin");
    address internal guardian = makeAddr("guardian");
    address internal workflow = makeAddr("workflow");
    address internal issuer = makeAddr("issuer");
    address internal holder = makeAddr("holder");
    address internal outsider = makeAddr("outsider");
    address internal operator = makeAddr("operator");

    // ---------------------------------------------------------------------
    // Chain selectors
    // ---------------------------------------------------------------------
    uint64 internal constant SOURCE_SELECTOR = 16_015_286_601_757_825_753;
    uint64 internal constant DEST_SELECTOR = 3_478_487_238_524_512_106;

    // ---------------------------------------------------------------------
    // System: source chain
    // ---------------------------------------------------------------------
    ComplianceRegistry internal sourceRegistry;
    ComplianceGateway internal sourceGateway;
    ProviderRegistry internal sourceProviders;
    PoolPolicyManager internal sourcePolicies;
    AuditTrail internal sourceAudit;
    CCIDResolver internal sourceResolver;
    EmergencyControls internal sourceEmergency;
    CrossChainComplianceSender internal sourceSenderContract;
    PoolComplianceModule internal sourceModule;
    MockCCIPRouter internal router;

    // ---------------------------------------------------------------------
    // System: destination chain
    // ---------------------------------------------------------------------
    ComplianceRegistry internal destRegistry;
    CrossChainComplianceReceiver internal destReceiver;
    ProviderRegistry internal destProviders;
    PoolPolicyManager internal destPolicies;
    EmergencyControls internal destEmergency;

    // ---------------------------------------------------------------------
    // Fixtures
    // ---------------------------------------------------------------------
    bytes32 internal constant CRED_TYPE = keccak256("kyc.basic");
    bytes32 internal constant PROVIDER_A = keccak256("provider.mock-kyc");
    bytes32 internal constant SUBJECT = keccak256("subject-commitment-alice");
    bytes32 internal constant EVIDENCE = keccak256("evidence-root");

    uint32 internal constant SCHEMA_VERSION = 1;
    uint64 internal constant TTL = 365 days;

    /// @dev ISO 3166-1 numeric: United States.
    uint16 internal constant JURISDICTION_US = 840;
    /// @dev ISO 3166-1 numeric: United Kingdom.
    uint16 internal constant JURISDICTION_UK = 826;

    uint64 internal constant T0 = 1_700_000_000;

    function setUp() public virtual {
        vm.warp(T0);

        router = new MockCCIPRouter();

        // Deployment wiring below (bridge binding, writer grants, role grants) is
        // admin-gated, so it all happens inside one impersonation.
        vm.startPrank(admin);

        // --- Source chain ---
        sourceRegistry = new ComplianceRegistry(admin);
        sourceProviders = new ProviderRegistry(admin);
        sourcePolicies = new PoolPolicyManager(admin);
        sourceAudit = new AuditTrail(admin);
        sourceResolver = new CCIDResolver();
        sourceEmergency = new EmergencyControls(admin, guardian);

        // The destination chain is a leaf: it receives replicas and has no issuer,
        // so no gateway is deployed for it. "Local issuance on the destination" is a
        // scenario rather than a deployment mode, and the propagation suite builds
        // its own third system to exercise it.

        sourceSenderContract = new CrossChainComplianceSender(admin, address(router), SOURCE_SELECTOR, sourceEmergency);
        sourceGateway = new ComplianceGateway(
            admin,
            sourceRegistry,
            sourceProviders,
            sourcePolicies,
            sourceResolver,
            sourceAudit,
            sourceSenderContract,
            sourceEmergency
        );

        // Break the gateway/sender constructor cycle.
        sourceSenderContract.initializeBridge(address(sourceGateway));
        sourceRegistry.setWriter(address(sourceGateway), true);

        // The gateway is not the trail's admin, so it cannot self-authorize; the
        // deployer does it after construction. See ComplianceGateway.isAuditAuthorized.
        sourceAudit.authorizeRecorder(address(sourceGateway));

        sourceModule =
            new PoolComplianceModule(sourceRegistry, sourceProviders, sourcePolicies, sourceEmergency, sourceAudit);
        sourceAudit.authorizeRecorder(address(sourceModule));

        // --- Destination chain ---
        destRegistry = new ComplianceRegistry(admin);
        destProviders = new ProviderRegistry(admin);
        destPolicies = new PoolPolicyManager(admin);
        destEmergency = new EmergencyControls(admin, guardian);

        destReceiver = new CrossChainComplianceReceiver(
            address(router), DEST_SELECTOR, admin, destRegistry, destProviders, destEmergency
        );
        destRegistry.setWriter(address(destReceiver), true);
        destReceiver.wire();

        // --- Roles ---
        sourceGateway.grantRole(sourceGateway.WORKFLOW_SUBMITTER(), workflow);
        sourceGateway.grantRole(sourceGateway.ISSUER(), issuer);
        sourceGateway.grantRole(sourceGateway.HOLDER(), holder);
        sourceProviders.grantRole(sourceProviders.PROVIDER_OPERATOR(), operator);

        // --- Registries, identical on both chains ---
        _seedProvider(sourceProviders, PROVIDER_A);
        _seedProvider(destProviders, PROVIDER_A);

        // --- Cross-chain trust ---
        destReceiver.setAllowedSourceSender(address(sourceGateway), true);
        destReceiver.setAllowedSourceChain(SOURCE_SELECTOR, true);
        destSelector = destReceiver.selector();

        vm.stopPrank();
    }

    // ---------------------------------------------------------------------
    // Seeding
    // ---------------------------------------------------------------------

    function _seedProvider(ProviderRegistry providers, bytes32 providerId) internal {
        providers.registerProvider(providerId, "https://example.invalid/provider");
        providers.setProviderStatus(providerId, ProviderRegistry.ProviderStatus.Active);
        providers.setSchemaSupport(providerId, CRED_TYPE, SCHEMA_VERSION, true);
    }

    /**
     * @dev Register and activate a policy for `poolId`.
     *
     *      Activation is timelocked by `POLICY_ACTIVATION_DELAY`, so this warps past
     *      it. Tests that care about the delay itself use the manager directly.
     */
    /**
     * @dev Register and activate a policy for `poolId`.
     *
     *      Policy registration and activation are both `ISSUER_ADMIN`-gated and
     *      impersonate `admin`, so a caller cannot distinguish this helper's own
     *      authorization from a caller's. Activation is timelocked by
     *      `POLICY_ACTIVATION_DELAY`, so this warps past it; tests that care about the
     *      delay itself drive {PoolPolicyManager} directly.
     */
    function _seedPolicy(
        bytes32 poolId,
        bool requiresManualReview,
        uint16[] memory jurisdictions,
        ComplianceTypes.InvestorClass[] memory classes,
        bool requiresFresh,
        uint64 maxReplicaAge,
        uint256 maxAllocation,
        ComplianceTypes.RevocationMode revocationMode
    ) internal {
        vm.startPrank(admin);
        uint32 next = sourcePolicies.latestVersion(poolId) + 1;
        sourcePolicies.registerPolicy(
            poolId,
            requiresManualReview,
            jurisdictions,
            classes,
            requiresFresh,
            maxReplicaAge,
            maxAllocation,
            revocationMode,
            0
        );
        vm.warp(block.timestamp + sourcePolicies.POLICY_ACTIVATION_DELAY() + 1);
        sourcePolicies.activatePolicyVersion(poolId, next);
        vm.stopPrank();
    }

    /// @dev A permissive policy: all jurisdictions, accredited + non-US professionals.
    function _seedPermissivePolicy(bytes32 poolId) internal {
        ComplianceTypes.InvestorClass[] memory classes = new ComplianceTypes.InvestorClass[](2);
        classes[0] = ComplianceTypes.InvestorClass.USAccredited;
        classes[1] = ComplianceTypes.InvestorClass.NonUSProfessional;
        _seedPolicy(poolId, false, new uint16[](0), classes, false, 0, 0, ComplianceTypes.RevocationMode.IssuerOnly);
    }

    // ---------------------------------------------------------------------
    // Result construction
    // ---------------------------------------------------------------------

    function _result(
        bytes32 subjectCommitment,
        uint64 nonce,
        uint16 jurisdictionCode,
        ComplianceTypes.InvestorClass investorClass
    ) internal view returns (ComplianceTypes.CredentialResult memory) {
        uint64 issuedAt = uint64(block.timestamp);
        return ComplianceTypes.CredentialResult({
            ccid: sourceResolver.compute(
                CRED_TYPE, SCHEMA_VERSION, PROVIDER_A, jurisdictionCode, investorClass, subjectCommitment
            ),
            credentialType: CRED_TYPE,
            providerId: PROVIDER_A,
            subjectCommitment: subjectCommitment,
            evidenceHash: EVIDENCE,
            schemaVersion: SCHEMA_VERSION,
            jurisdictionCode: jurisdictionCode,
            investorClass: investorClass,
            issuedAt: issuedAt,
            expiresAt: issuedAt + TTL,
            nonce: nonce,
            destinationChainSelectors: new uint64[](0)
        });
    }

    function _resultWithDestinations(
        bytes32 subjectCommitment,
        uint64 nonce,
        uint16 jurisdictionCode,
        ComplianceTypes.InvestorClass investorClass,
        uint64[] memory destinations
    ) internal view returns (ComplianceTypes.CredentialResult memory) {
        ComplianceTypes.CredentialResult memory r = _result(subjectCommitment, nonce, jurisdictionCode, investorClass);
        r.destinationChainSelectors = destinations;
        return r;
    }

    /// @dev A valid US-accredited result.
    function _defaultResult(bytes32 subjectCommitment, uint64 nonce)
        internal
        view
        returns (ComplianceTypes.CredentialResult memory)
    {
        return _result(subjectCommitment, nonce, JURISDICTION_US, ComplianceTypes.InvestorClass.USAccredited);
    }

    /// @dev Issue a valid credential as the workflow, returning its CCID.
    function _issue(bytes32 subjectCommitment, uint64 nonce) internal returns (bytes32 ccid) {
        ComplianceTypes.CredentialResult memory r = _defaultResult(subjectCommitment, nonce);
        vm.prank(workflow);
        sourceGateway.submitCredentialResult(r);
        return r.ccid;
    }

    // ---------------------------------------------------------------------
    // Access requests
    // ---------------------------------------------------------------------

    function _request(bytes32 ccid, bytes32 poolId) internal pure returns (ComplianceTypes.AccessRequest memory) {
        return ComplianceTypes.AccessRequest({ccid: ccid, poolId: poolId, requestedAmount: 0, currentAllocation: 0});
    }

    function _requestWithAmount(bytes32 ccid, bytes32 poolId, uint256 amount, uint256 current)
        internal
        pure
        returns (ComplianceTypes.AccessRequest memory)
    {
        return ComplianceTypes.AccessRequest({
            ccid: ccid, poolId: poolId, requestedAmount: amount, currentAllocation: current
        });
    }

    // ---------------------------------------------------------------------
    // Propagation helpers
    // ---------------------------------------------------------------------

    function _sentCount() internal view returns (uint256) {
        return router.sentCount();
    }

    /// @dev Cached receiver selector. Read once rather than inside the delivery
    ///      helper, because an intervening call would silently consume a pending
    ///      `vm.expectRevert` and make every rejection test pass vacuously.
    bytes4 internal destSelector;

    function _deliver(uint256 index, address sender, bytes32 orderId) internal {
        router.deliver(index, address(destReceiver), sender, orderId, destSelector);
    }
}
