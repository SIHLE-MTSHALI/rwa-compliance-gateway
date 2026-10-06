// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

import {AuditTrail} from "../src/AuditTrail.sol";
import {CCIDResolver} from "../src/CCIDResolver.sol";
import {ComplianceGateway} from "../src/ComplianceGateway.sol";
import {ComplianceRegistry} from "../src/ComplianceRegistry.sol";
import {CrossChainComplianceReceiver} from "../src/CrossChainComplianceReceiver.sol";
import {CrossChainComplianceSender} from "../src/CrossChainComplianceSender.sol";
import {EmergencyControls} from "../src/EmergencyControls.sol";
import {PoolComplianceModule} from "../src/PoolComplianceModule.sol";
import {PoolPolicyManager} from "../src/PoolPolicyManager.sol";
import {ProviderRegistry} from "../src/ProviderRegistry.sol";

/**
 * @title Deploy
 * @notice Deploys the compliance gateway and prints the wiring order it performed.
 *
 * @dev ## Two circular dependencies, and how they are broken
 *
 *      The system has two reference cycles that no constructor argument list can
 *      satisfy, because each contract must hold the other's address:
 *
 *      1. **Gateway <-> sender.** The gateway dispatches propagation, and the sender
 *         must know which gateway is allowed to dispatch. Resolved by deploying the
 *         sender first with an unset bridge and calling
 *         {CrossChainComplianceSender.initializeBridge} afterwards - one-time,
 *         deployer-only, and permanent, so a compromised deployer key cannot redirect
 *         propagation later.
 *
 *      2. **Receiver <-> registry.** The receiver writes to the registry, so it needs
 *         `WRITER_ROLE`. The role is granted to the receiver's address, which only
 *         exists after construction. Resolved by {CrossChainComplianceReceiver.wire},
 *         which verifies the role really was granted before arming - so a deployment
 *         that skipped the grant refuses inbound messages loudly instead of silently
 *         dropping them.
 *
 * @dev ## The step that is easy to miss
 *
 *      `AuditTrail.authorizeRecorder(gateway)` and `authorizeRecorder(module)` are
 *      separate calls the deployer must make. The gateway cannot self-authorize: the
 *      trail authorizes by *admin*, and the gateway is not its admin. Until both are
 *      done, every issuance and every recorded decision reverts.
 *
 *      That is the correct failure mode - a gateway that cannot record its own history
 *      is worse than one with no history, because the gap is invisible until someone
 *      audits - but it means a deployment script that forgets the step produces a
 *      system that looks deployed and refuses all work. The script asserts it at the end.
 *
 * @dev ## Configuration
 *
 *      Read from the environment so the same script serves every chain:
 *
 *      ```
 *      DEPLOYER            the broadcasting key (forge handles this)
 *      ADMIN               governance address
 *      GUARDIAN            emergency-pause address; must not be the same as ADMIN
 *      CCIP_ROUTER         Chainlink CCIP v2 router
 *      SOURCE_CHAIN_SELECTOR  this chain's CCIP selector
 *      DEPLOY_RECEIVER     "true" to also deploy the inbound receiver
 *      ```
 *
 *      `GUARDIAN` defaulting to `ADMIN` is refused rather than allowed. A single key
 *      that can both stop the system and control it is not an emergency control, and
 *      the mistake is easy to make by forgetting the variable.
 */
contract Deploy is Script {
    function run() external {
        address admin = vm.envOr("ADMIN", msg.sender);
        address guardian = vm.envOr("GUARDIAN", address(0));
        address router = vm.envOr("CCIP_ROUTER", address(0));
        uint64 sourceChainSelector = uint64(vm.envOr("SOURCE_CHAIN_SELECTOR", uint256(0)));
        bool deployReceiver = vm.envOr("DEPLOY_RECEIVER", false);

        // A guardian that is also the admin collapses the pause/resume asymmetry, so
        // the default is a refusal rather than a silent fallback.
        if (guardian == address(0)) {
            revert GuardianNotConfigured();
        }
        if (guardian == admin) {
            revert GuardianMustDifferFromAdmin(admin);
        }
        if (router == address(0)) {
            revert RouterNotConfigured();
        }
        if (sourceChainSelector == 0) {
            revert SourceChainSelectorNotConfigured();
        }

        vm.startBroadcast();

        // --- Registries and policy -----------------------------------------------------
        ComplianceRegistry registry = new ComplianceRegistry(admin);
        ProviderRegistry providers = new ProviderRegistry(admin);
        PoolPolicyManager policies = new PoolPolicyManager(admin);
        AuditTrail audit = new AuditTrail(admin);
        CCIDResolver resolver = new CCIDResolver();
        EmergencyControls emergency = new EmergencyControls(admin, guardian);

        // --- Sender, then the gateway that binds to it ---------------------------------
        CrossChainComplianceSender sender =
            new CrossChainComplianceSender(admin, router, sourceChainSelector, emergency);

        ComplianceGateway gateway =
            new ComplianceGateway(admin, registry, providers, policies, resolver, audit, sender, emergency);

        // --- Break the cycles -----------------------------------------------------------
        sender.initializeBridge(address(gateway));
        registry.setWriter(address(gateway), true);
        audit.authorizeRecorder(address(gateway));

        // --- The access module integrators call -----------------------------------------
        PoolComplianceModule complianceModule =
            new PoolComplianceModule(registry, providers, policies, emergency, audit);
        audit.authorizeRecorder(address(complianceModule));

        CrossChainComplianceReceiver receiver;
        if (deployReceiver) {
            receiver =
                new CrossChainComplianceReceiver(router, sourceChainSelector, admin, registry, providers, emergency);
            registry.setWriter(address(receiver), true);

            address trustedSender = vm.envOr("TRUSTED_SOURCE_SENDER", address(0));
            if (trustedSender != address(0)) {
                receiver.setAllowedSourceSender(trustedSender, true);
                receiver.setAllowedSourceChain(uint64(vm.envOr("TRUSTED_SOURCE_SELECTOR", uint256(0))), true);
            }
            receiver.wire();
        }

        vm.stopBroadcast();

        // --- Postconditions --------------------------------------------------------------
        //
        // Asserted rather than logged. Every one of these is a step whose absence leaves a
        // system that looks deployed and fails later, in production, on the first
        // transaction that needs it.
        require(gateway.isAuditAuthorized(), "gateway is not an audit recorder");
        require(audit.hasRole(audit.AUDITOR_ROLE(), address(complianceModule)), "module is not a recorder");
        require(sender.bridge() == address(gateway), "sender is not bound to the gateway");
        require(registry.isWriter(address(gateway)), "gateway is not a registry writer");
        require(!emergency.isPaused(), "system must not deploy paused");

        _report(
            address(registry),
            address(providers),
            address(policies),
            address(audit),
            address(resolver),
            address(emergency),
            address(sender),
            address(gateway),
            address(complianceModule),
            address(receiver),
            sourceChainSelector
        );
    }

    /// @dev Foundry's `console.log` has no format specifiers, so every interpolated
    ///      value has to be converted explicitly. Verbose, but it means a deployment
    ///      transcript is greppable for an address.
    function _report(
        address registry,
        address providers,
        address policies,
        address audit,
        address resolver,
        address emergency,
        address sender,
        address gateway,
        address complianceModule,
        address receiver,
        uint64 sourceChainSelector
    ) private pure {
        console.log("ComplianceRegistry             ", registry);
        console.log("ProviderRegistry               ", providers);
        console.log("PoolPolicyManager              ", policies);
        console.log("AuditTrail                     ", audit);
        console.log("CCIDResolver                   ", resolver);
        console.log("EmergencyControls              ", emergency);
        console.log("CrossChainComplianceSender     ", sender);
        console.log("ComplianceGateway              ", gateway);
        console.log("PoolComplianceModule           ", complianceModule);
        if (receiver != address(0)) console.log("CrossChainComplianceReceiver   ", receiver);
        console.log("SOURCE_CHAIN_SELECTOR          ", vm.toString(sourceChainSelector));
        console.log("");
        console.log("next: register a provider, then a pool policy, then activate it after the delay");
        console.log("      PoolPolicyManager.POLICY_ACTIVATION_DELAY is a week; plan the rollout");
    }

    error GuardianNotConfigured();
    error GuardianMustDifferFromAdmin(address admin);
    error RouterNotConfigured();
    error SourceChainSelectorNotConfigured();
}
