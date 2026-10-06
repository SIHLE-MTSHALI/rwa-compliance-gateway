// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ProviderRegistry} from "../src/ProviderRegistry.sol";
import {Test} from "forge-std/Test.sol";

/**
 * @title ProviderRegistryTest
 * @notice Provider registration, status transitions, schema support, and health.
 *
 * @dev ## The distinction this suite is built around
 *
 *      `Paused`, `Deprecated`, and `Revoked` all deny issuance, and only two of
 *      them deny existing credentials too. That difference is the reason
 *      {ProviderRegistry.backsExistingCredentials} exists, and it is easy to get
 *      wrong in the direction that punishes every existing holder during a routine
 *      provider migration.
 */
contract ProviderRegistryTest is Test {
    ProviderRegistry internal registry;

    address internal admin = makeAddr("admin");
    address internal operator = makeAddr("operator");
    address internal outsider = makeAddr("outsider");

    bytes32 internal constant PROVIDER_A = keccak256("provider.alpha");
    bytes32 internal constant CRED_TYPE = keccak256("kyc.basic");

    function setUp() public {
        registry = new ProviderRegistry(admin);
        // Hoisted: `registry.PROVIDER_OPERATOR()` is an external call, and inline it
        // would spend the pending prank. See CheatcodeSemanticsTest.
        bytes32 operatorRole = registry.PROVIDER_OPERATOR();
        vm.prank(admin);
        registry.grantRole(operatorRole, operator);
    }

    function test_RolesAreHandoverable() public {
        // `AccessControl` resolves a role's admin to `bytes32(0)` unless declared,
        // and no account holds that. Without the explicit `_setRoleAdmin` wiring in
        // the constructor this grant would revert, and a provider-admin or operator
        // key could never be rotated after deployment.
        bytes32 operatorRole = registry.PROVIDER_OPERATOR();
        bytes32 providerAdmin = registry.PROVIDER_ADMIN();
        bytes32 root = registry.DEFAULT_ADMIN_ROLE();

        assertEq(registry.getRoleAdmin(providerAdmin), root);
        assertEq(registry.getRoleAdmin(operatorRole), providerAdmin);

        address successor = makeAddr("successor");
        vm.prank(admin);
        registry.grantRole(providerAdmin, successor);
        vm.prank(successor);
        registry.grantRole(operatorRole, successor);
        assertTrue(registry.hasRole(operatorRole, successor));
    }

    function test_NonAdminCannotGrantOperatorRole() public {
        bytes32 operatorRole = registry.PROVIDER_OPERATOR();
        vm.prank(outsider);
        vm.expectRevert();
        registry.grantRole(operatorRole, outsider);
    }

    function _register(bytes32 providerId) internal {
        vm.prank(admin);
        registry.registerProvider(providerId, "https://example.invalid/adapter");
    }

    function _activate(bytes32 providerId) internal {
        vm.prank(admin);
        registry.setProviderStatus(providerId, ProviderRegistry.ProviderStatus.Active);
    }

    // -----------------------------------------------------------------
    // Registration
    // -----------------------------------------------------------------

    function test_NewProviderStartsPaused() public {
        // An adapter must be reviewed and explicitly activated before it can
        // influence any decision. Starting `Active` would make registration alone a
        // trust decision.
        _register(PROVIDER_A);
        assertEq(uint8(registry.getProviderStatus(PROVIDER_A)), uint8(ProviderRegistry.ProviderStatus.Paused));
        assertTrue(registry.getProvider(PROVIDER_A).registered);
        assertFalse(registry.isActive(PROVIDER_A));
        assertFalse(registry.supportsSchema(PROVIDER_A, CRED_TYPE, 1));
    }

    function test_RegisterStoresMetadata() public {
        _register(PROVIDER_A);
        ProviderRegistry.Provider memory p = registry.getProvider(PROVIDER_A);
        assertEq(p.metadataURI, "https://example.invalid/adapter");
        assertEq(p.providerId, PROVIDER_A);
        assertEq(p.registeredAt, uint64(block.timestamp));
    }

    function test_DuplicateRegistrationRejected() public {
        _register(PROVIDER_A);
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(ProviderRegistry.ProviderAlreadyRegistered.selector, PROVIDER_A));
        registry.registerProvider(PROVIDER_A, "https://example.invalid/again");
    }

    function test_EmptyProviderIdRejected() public {
        vm.prank(admin);
        vm.expectRevert(ProviderRegistry.EmptyProviderId.selector);
        registry.registerProvider(bytes32(0), "https://example.invalid/adapter");
    }

    function test_MetadataUriLengthBounded() public {
        // Bound hoisted: reading it inline would spend the pending prank.
        uint256 maxLength = registry.MAX_METADATA_URI_LENGTH();
        bytes memory long = new bytes(maxLength + 1);
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(ProviderRegistry.MetadataUriTooLong.selector, maxLength + 1));
        registry.registerProvider(PROVIDER_A, string(long));
    }

    function test_MetadataUriAtLimitAccepted() public {
        uint256 maxLength = registry.MAX_METADATA_URI_LENGTH();
        bytes memory atLimit = new bytes(maxLength);
        vm.prank(admin);
        registry.registerProvider(PROVIDER_A, string(atLimit));
        assertTrue(registry.getProvider(PROVIDER_A).registered);
    }

    function test_NonAdminCannotRegister() public {
        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(ProviderRegistry.NotProviderAdmin.selector, outsider));
        registry.registerProvider(PROVIDER_A, "https://example.invalid/adapter");
    }

    function test_MetadataCanBeUpdated() public {
        _register(PROVIDER_A);
        vm.prank(admin);
        registry.setMetadataURI(PROVIDER_A, "https://example.invalid/v2");
        assertEq(registry.getProvider(PROVIDER_A).metadataURI, "https://example.invalid/v2");
    }

    // -----------------------------------------------------------------
    // The Paused / Deprecated / Revoked matrix
    // -----------------------------------------------------------------

    function test_OnlyActiveAllowsIssuance() public {
        _register(PROVIDER_A);
        assertFalse(registry.isActive(PROVIDER_A));
        _activate(PROVIDER_A);
        assertTrue(registry.isActive(PROVIDER_A));
    }

    function test_DeprecatedBlocksIssuanceButBacksExistingCredentials() public {
        // The distinction that stops a routine provider migration from
        // invalidating every live credential.
        _register(PROVIDER_A);
        vm.prank(admin);
        registry.setProviderStatus(PROVIDER_A, ProviderRegistry.ProviderStatus.Deprecated);

        assertFalse(registry.isActive(PROVIDER_A), "no new issuance");
        assertTrue(registry.backsExistingCredentials(PROVIDER_A), "but existing ones stand");
    }

    function test_RevokedBlocksEverything() public {
        // Issued on compromise: the adapter's attestations are no longer trusted at
        // all, so credentials it signed cannot stand either.
        _register(PROVIDER_A);
        _activate(PROVIDER_A);
        vm.prank(admin);
        registry.setProviderStatus(PROVIDER_A, ProviderRegistry.ProviderStatus.Revoked);

        assertFalse(registry.isActive(PROVIDER_A));
        assertFalse(registry.backsExistingCredentials(PROVIDER_A));
    }

    function test_PausedBlocksEverything() public {
        _register(PROVIDER_A);
        _activate(PROVIDER_A);
        vm.prank(admin);
        registry.setProviderStatus(PROVIDER_A, ProviderRegistry.ProviderStatus.Paused);

        assertFalse(registry.isActive(PROVIDER_A));
        assertFalse(registry.backsExistingCredentials(PROVIDER_A));
    }

    function test_BacksExistingCredentialsFalseForUnregistered() public {
        assertFalse(registry.backsExistingCredentials(keccak256("never-registered")));
    }

    function test_ReactivationClearsFailureCounter() public {
        // An operator bringing a provider back should not inherit an unbounded
        // stale alert from the outage it just recovered from.
        _register(PROVIDER_A);
        _activate(PROVIDER_A);
        vm.startPrank(operator);
        registry.reportFailure(PROVIDER_A);
        registry.reportFailure(PROVIDER_A);
        vm.stopPrank();
        assertEq(registry.getProvider(PROVIDER_A).failureCount, 2);
        assertFalse(registry.isProviderHealthy(PROVIDER_A));

        vm.prank(admin);
        registry.setProviderStatus(PROVIDER_A, ProviderRegistry.ProviderStatus.Paused);
        vm.prank(admin);
        registry.setProviderStatus(PROVIDER_A, ProviderRegistry.ProviderStatus.Active);

        assertEq(registry.getProvider(PROVIDER_A).failureCount, 0);
    }

    /**
     * @dev An out-of-range status cannot reach the function body: solc's ABI decoder
     *      validates enum parameters and rejects the call before the body runs.
     *
     *      Asserted rather than assumed, because it is what licenses
     *      {ProviderRegistry.setProviderStatus} to carry no in-body range check. If a
     *      future toolchain relaxed this, the call would succeed, write an
     *      out-of-range `uint8` to storage, and make `getProviderStatus`'s enum
     *      decode panic - so this test is the guard on that.
     *
     *      The revert carries **no return data**: solc's decoder does a bare
     *      `revert(0, 0)` rather than `Panic(0x21)`. Worth pinning, because in a raw
     *      trace that is indistinguishable from an out-of-gas, and a future change to
     *      `Panic` would be a behaviour change worth noticing.
     */
    function test_OutOfRangeStatusRejectedViaRawCalldata() public {
        _register(PROVIDER_A);
        bytes memory data = abi.encodeWithSelector(registry.setProviderStatus.selector, PROVIDER_A, uint8(99));

        vm.prank(admin);
        (bool ok, bytes memory ret) = address(registry).call(data);

        assertFalse(ok, "an out-of-range enum must not be accepted");
        assertEq(ret.length, 0, "rejected by the ABI decoder, which reverts without data");
        assertEq(
            uint8(registry.getProviderStatus(PROVIDER_A)),
            uint8(ProviderRegistry.ProviderStatus.Paused),
            "storage unchanged"
        );
    }

    function test_StatusChangeOnUnregisteredRejected() public {
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(ProviderRegistry.ProviderNotRegistered.selector, PROVIDER_A));
        registry.setProviderStatus(PROVIDER_A, ProviderRegistry.ProviderStatus.Active);
    }

    // -----------------------------------------------------------------
    // Schema support
    // -----------------------------------------------------------------

    function test_SchemaSupportIsPerTypeAndVersion() public {
        _register(PROVIDER_A);
        vm.startPrank(admin);
        registry.setSchemaSupport(PROVIDER_A, CRED_TYPE, 1, true);
        registry.setSchemaSupport(PROVIDER_A, CRED_TYPE, 2, false);
        registry.setSchemaSupport(PROVIDER_A, keccak256("kyb.enhanced"), 1, false);
        vm.stopPrank();

        assertTrue(registry.supportsSchema(PROVIDER_A, CRED_TYPE, 1));
        assertFalse(registry.supportsSchema(PROVIDER_A, CRED_TYPE, 2));
        assertFalse(registry.supportsSchema(PROVIDER_A, keccak256("kyb.enhanced"), 1));
    }

    function test_SchemaSupportCanBeWithdrawn() public {
        _register(PROVIDER_A);
        vm.startPrank(admin);
        registry.setSchemaSupport(PROVIDER_A, CRED_TYPE, 1, true);
        registry.setSchemaSupport(PROVIDER_A, CRED_TYPE, 1, false);
        vm.stopPrank();
        assertFalse(registry.supportsSchema(PROVIDER_A, CRED_TYPE, 1));
    }

    function test_SchemaSupportOnUnregisteredRejected() public {
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(ProviderRegistry.ProviderNotRegistered.selector, PROVIDER_A));
        registry.setSchemaSupport(PROVIDER_A, CRED_TYPE, 1, true);
    }

    // -----------------------------------------------------------------
    // Health
    // -----------------------------------------------------------------

    function test_HeartbeatRecordsTimestamp() public {
        _register(PROVIDER_A);
        _activate(PROVIDER_A);
        vm.prank(operator);
        registry.heartbeat(PROVIDER_A);
        assertEq(registry.getProvider(PROVIDER_A).lastHeartbeat, uint64(block.timestamp));
        assertEq(registry.heartbeatAge(PROVIDER_A), 0);
        assertTrue(registry.isProviderHealthy(PROVIDER_A));
    }

    function test_HeartbeatStalenessIsAMonitoringSignalNotADenial() public {
        // Health deliberately does not feed the access path: denying on liveness
        // would let a missed heartbeat become a denial of service against every
        // holder served by that provider.
        _register(PROVIDER_A);
        _activate(PROVIDER_A);
        vm.prank(operator);
        registry.heartbeat(PROVIDER_A);

        vm.warp(block.timestamp + registry.HEARTBEAT_STALENESS_SECONDS() + 1);

        assertFalse(registry.isProviderHealthy(PROVIDER_A), "monitoring sees the problem");
        assertTrue(registry.isActive(PROVIDER_A), "but issuance is unaffected");
        assertTrue(registry.backsExistingCredentials(PROVIDER_A), "and existing credentials stand");
        assertEq(registry.heartbeatAge(PROVIDER_A), registry.HEARTBEAT_STALENESS_SECONDS() + 1);
    }

    function test_HeartbeatAgeSaturatesWhenNeverSeen() public {
        assertEq(registry.heartbeatAge(PROVIDER_A), type(uint64).max);
    }

    function test_HeartbeatRejectsOutOfOrderReports() public {
        _register(PROVIDER_A);
        _activate(PROVIDER_A);
        vm.warp(1_700_000_000);
        vm.prank(operator);
        registry.heartbeat(PROVIDER_A);

        // `vm.getBlockTimestamp()`, not `block.timestamp`: see CheatcodeSemanticsTest.
        uint64 observed = uint64(vm.getBlockTimestamp());

        vm.warp(observed - 10);
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(ProviderRegistry.StaleHeartbeat.selector, observed, observed - 10));
        registry.heartbeat(PROVIDER_A);
    }

    function test_RepeatedHeartbeatAllowed() public {
        _register(PROVIDER_A);
        _activate(PROVIDER_A);
        vm.warp(1_700_000_000);
        vm.prank(operator);
        registry.heartbeat(PROVIDER_A);
        vm.warp(1_700_000_060);
        vm.prank(operator);
        registry.heartbeat(PROVIDER_A);
        assertEq(registry.getProvider(PROVIDER_A).lastHeartbeat, 1_700_000_060);
    }

    function test_FailureCountAccumulates() public {
        _register(PROVIDER_A);
        _activate(PROVIDER_A);
        vm.prank(operator);
        registry.heartbeat(PROVIDER_A);
        assertTrue(registry.isProviderHealthy(PROVIDER_A));

        vm.prank(operator);
        registry.reportFailure(PROVIDER_A);
        assertFalse(registry.isProviderHealthy(PROVIDER_A), "an unresolved failure is not healthy");
        assertTrue(registry.isActive(PROVIDER_A), "but still trusted for issuance decisions");
    }

    function test_HealthRequiresEveryCondition() public {
        // Unregistered.
        assertFalse(registry.isProviderHealthy(PROVIDER_A));

        // Registered but paused.
        _register(PROVIDER_A);
        assertFalse(registry.isProviderHealthy(PROVIDER_A));

        // Active but no heartbeat ever recorded.
        _activate(PROVIDER_A);
        assertFalse(registry.isProviderHealthy(PROVIDER_A));

        // Active with a fresh heartbeat.
        vm.prank(operator);
        registry.heartbeat(PROVIDER_A);
        assertTrue(registry.isProviderHealthy(PROVIDER_A));
    }

    function test_OnlyOperatorMayReportHealth() public {
        _register(PROVIDER_A);
        _activate(PROVIDER_A);
        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(ProviderRegistry.NotProviderOperator.selector, outsider));
        registry.heartbeat(PROVIDER_A);

        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(ProviderRegistry.NotProviderOperator.selector, outsider));
        registry.reportFailure(PROVIDER_A);
    }

    /**
     * @dev Roles are separate, and deliberately so.
     *
     *      The admin holds `PROVIDER_ADMIN` - which can change provider status - but
     *      not `PROVIDER_OPERATOR`. Granting the latter is a separate, narrower
     *      decision, so "who may mark this adapter as failing" is a distinct question
     *      from "who may wind the adapter down".
     *
     *      Asserted rather than assumed because the obvious expectation (that the
     *      admin can do everything) is exactly the assumption that would hide a
     *      mis-scoped role.
     */
    function test_AdminIsNotImplicitlyAnOperator() public {
        _register(PROVIDER_A);
        _activate(PROVIDER_A);

        bytes32 operatorRole = registry.PROVIDER_OPERATOR();
        assertFalse(registry.hasRole(operatorRole, admin));

        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(ProviderRegistry.NotProviderOperator.selector, admin));
        registry.heartbeat(PROVIDER_A);

        // ...and granting it works, so the separation is a policy rather than a wall.
        vm.prank(admin);
        registry.grantRole(operatorRole, admin);
        vm.prank(admin);
        registry.heartbeat(PROVIDER_A);
        assertEq(registry.getProvider(PROVIDER_A).lastHeartbeat, uint64(vm.getBlockTimestamp()));
    }

    function test_ZeroAdminRejected() public {
        vm.expectRevert(ProviderRegistry.InvalidAdminAddress.selector);
        new ProviderRegistry(address(0));
    }
}
