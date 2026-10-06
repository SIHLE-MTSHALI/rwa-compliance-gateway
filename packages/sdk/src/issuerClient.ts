import type { Address, Hex, WalletClient, Chain } from "viem";
import { getContract } from "viem";

import { computeCcid, validateCcidParts, type CcidInput } from "./ccid.js";
import { CredentialStatus, InvestorClass } from "./reasons.js";

/**
 * Issuer-side operations: verification, issuance, renewal, and lifecycle changes.
 *
 * ## The boundary this client sits on
 *
 * Everything here is what a Chainlink workflow or an issuer key does. The workflow runs
 * off-chain, outside the boundary the contracts can reason about, so the gateway
 * re-derives and re-checks everything it is handed. That means a compromised workflow
 * can **refuse** a credential but cannot invent one, extend its life, misstate a
 * jurisdiction, or attribute it to a paused provider. Its worst outcome is denial of
 * service, which is bounded and recoverable by rotating the role.
 *
 * This client does not weaken that. It computes the CCID and lets the gateway verify it,
 * rather than presenting the CCID as an authority.
 */

export const GATEWAY_ABI = [
  {
    type: "function",
    name: "beginVerification",
    stateMutability: "nonpayable",
    inputs: [
      { name: "ccid", type: "bytes32" },
      { name: "credentialType", type: "bytes32" },
      { name: "schemaVersion", type: "uint32" },
      { name: "ttlSeconds", type: "uint64" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "submitCredentialResult",
    stateMutability: "nonpayable",
    inputs: [
      {
        name: "r",
        type: "tuple",
        components: [
          { name: "ccid", type: "bytes32" },
          { name: "credentialType", type: "bytes32" },
          { name: "providerId", type: "bytes32" },
          { name: "subjectCommitment", type: "bytes32" },
          { name: "evidenceHash", type: "bytes32" },
          { name: "schemaVersion", type: "uint32" },
          { name: "jurisdictionCode", type: "uint16" },
          { name: "investorClass", type: "uint8" },
          { name: "issuedAt", type: "uint64" },
          { name: "expiresAt", type: "uint64" },
          { name: "nonce", type: "uint64" },
          { name: "destinationChainSelectors", type: "uint64[]" },
        ],
      },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "renewCredential",
    stateMutability: "nonpayable",
    inputs: [
      {
        name: "r",
        type: "tuple",
        components: [
          { name: "ccid", type: "bytes32" },
          { name: "credentialType", type: "bytes32" },
          { name: "providerId", type: "bytes32" },
          { name: "subjectCommitment", type: "bytes32" },
          { name: "evidenceHash", type: "bytes32" },
          { name: "schemaVersion", type: "uint32" },
          { name: "jurisdictionCode", type: "uint16" },
          { name: "investorClass", type: "uint8" },
          { name: "issuedAt", type: "uint64" },
          { name: "expiresAt", type: "uint64" },
          { name: "nonce", type: "uint64" },
          { name: "destinationChainSelectors", type: "uint64[]" },
        ],
      },
      { name: "destinations", type: "uint64[]" },
      { name: "newExpiresAt", type: "uint64" },
      { name: "newNonce", type: "uint64" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "revoke",
    stateMutability: "nonpayable",
    inputs: [
      { name: "ccid", type: "bytes32" },
      { name: "poolId", type: "bytes32" },
      { name: "reason", type: "bytes32" },
      { name: "destinations", type: "uint64[]" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "suspend",
    stateMutability: "nonpayable",
    inputs: [
      { name: "ccid", type: "bytes32" },
      { name: "reason", type: "bytes32" },
      { name: "destinations", type: "uint64[]" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "resume",
    stateMutability: "nonpayable",
    inputs: [
      { name: "ccid", type: "bytes32" },
      { name: "reason", type: "bytes32" },
      { name: "destinations", type: "uint64[]" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "isAuditAuthorized",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "bool" }],
  },
] as const;

export const REGISTRY_ABI = [
  {
    type: "function",
    name: "expireDue",
    stateMutability: "nonpayable",
    inputs: [{ name: "ccids", type: "bytes32[]" }],
    outputs: [{ name: "expiredCount", type: "uint256" }],
  },
  {
    type: "function",
    name: "MAX_SWEEP_BATCH",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint256" }],
  },
] as const;

/** Everything the gateway needs about a verified credential. */
export interface CredentialResultInput extends CcidInput {
  /**
   * Commitment to the provider's evidence. The evidence itself never goes on chain - see
   * `docs/privacy-model.md`.
   */
  readonly evidenceHash: Hex;
  /** Defaults to now. */
  readonly issuedAt?: bigint;
  readonly expiresAt: bigint;
  /** Must strictly increase for this CCID. Replay guard. */
  readonly nonce: bigint;
  /** CCIP chain selectors to propagate to. Empty means single-chain. */
  readonly destinations?: readonly bigint[];
}

function toResultTuple(input: CredentialResultInput, destinationChainSelectors: readonly bigint[]) {
  return {
    ccid: computeCcid(input),
    credentialType: input.credentialType,
    providerId: input.providerId,
    subjectCommitment: input.subjectCommitment,
    evidenceHash: input.evidenceHash,
    schemaVersion: input.schemaVersion,
    jurisdictionCode: input.jurisdictionCode,
    investorClass: input.investorClass,
    issuedAt: input.issuedAt ?? 0n,
    expiresAt: input.expiresAt,
    nonce: input.nonce,
    destinationChainSelectors: [...destinationChainSelectors],
  } as const;
}

/** Contract handles built by named factories so ABI inference survives the field
 *  annotation - see the note in `complianceClient.ts`. */
function gatewayContract(client: WalletClient, address: Address, chain?: Chain) {
  return getContract({ abi: GATEWAY_ABI, address, client, ...(chain ? { chain } : {}) });
}

function registryWriteContract(client: WalletClient, address: Address, chain?: Chain) {
  return getContract({ abi: REGISTRY_ABI, address, client, ...(chain ? { chain } : {}) });
}

export interface IssuerClientOptions {
  readonly walletClient: WalletClient;
  /** The signer whose role authorises these calls. Never inferred from a default. */
  readonly account: Address;
  readonly gatewayAddress: Address;
  readonly registryAddress: Address;
  readonly chain?: Chain;
}

export class IssuerClient {
  private readonly gateway: ReturnType<typeof gatewayContract>;
  private readonly registry: ReturnType<typeof registryWriteContract>;

  /**
   * Passed on every write.
   *
   * viem's contract writer requires an explicit options object rather than falling back
   * to a client default, which is the better behaviour for a compliance client: a
   * lifecycle call should never be sent from an account nobody chose. The account is
   * fixed at construction, so it cannot drift between calls.
   */
  /**
   * `chain` is carried even though it is often `undefined`.
   *
   * viem's contract writer requires it in the options object when the client is
   * generic - passing `{ account }` alone fails to typecheck. Passing it through
   * unchanged keeps the chain the client is bound to, so a transaction cannot be sent to
   * a different chain than the one the client was built for.
   */
  private readonly writeOptions: { account: Address; chain: Chain | undefined };

  constructor(options: IssuerClientOptions) {
    this.gateway = gatewayContract(options.walletClient, options.gatewayAddress, options.chain);
    this.registry = registryWriteContract(options.walletClient, options.registryAddress, options.chain);
    this.writeOptions = { account: options.account, chain: options.chain };
  }

  /**
   * True when this gateway may write to the audit trail.
   *
   * Worth checking after deployment and in a health check: until the deployer has called
   * `AuditTrail.authorizeRecorder(gateway)`, **every** issuance reverts on the audit
   * hook. That is the correct failure mode - a gateway that cannot record its own history
   * is worse than one with no history, because the gap is invisible until someone audits
   * - but it is a silent-looking failure to anyone who has not read `Deploy.s.sol`.
   */
  async isAuditAuthorized(): Promise<boolean> {
    return this.gateway.read.isAuditAuthorized();
  }

  /**
   * Open a credential in `Pending` while verification runs.
   *
   * Lets a holder see that a check is in flight rather than observing `NO_CREDENTIAL` and
   * being unable to distinguish "not requested" from "requested, still running".
   *
   * `Pending` **denies** access. It is not a provisional allow.
   */
  async beginVerification(
    input: CcidInput & { ttlSeconds: bigint },
  ): Promise<{ ccid: Hex; hash: Hex }> {
    const ccid = computeCcid(input);
    const hash = await this.gateway.write.beginVerification(
      [ccid, input.credentialType, input.schemaVersion, input.ttlSeconds],
      this.writeOptions,
    );
    return { ccid, hash };
  }

  /**
   * Submit a verified credential result.
   *
   * Resolves a `Pending` record if one exists, otherwise creates one. The gateway
   * re-derives the CCID from these fields and rejects the submission if it does not
   * match, so the `ccid` computed here is a convenience rather than an authority.
   */
  async submit(input: CredentialResultInput): Promise<{ ccid: Hex; hash: Hex }> {
    // Checked locally so the failure names the actual problem. The gateway rejects a zero
    // subject commitment too, but only as `ZeroEvidenceHash`-style enum-free guards that
    // read as an opaque revert.
    if (!validateCcidParts(input)) {
      throw new Error(
        "credentialType, providerId, and subjectCommitment must all be non-zero; " +
          "a zero subject commitment would leave the credential bound to nobody",
      );
    }

    const ccid = computeCcid(input);
    const hash = await this.gateway.write.submitCredentialResult(
      [toResultTuple(input, input.destinations ?? [])],
      this.writeOptions,
    );
    return { ccid, hash };
  }

  /**
   * Renew after fresh provider verification.
   *
   * The result must satisfy every issuance check, so renewal is impossible without a
   * provider attestation that passes the full gate. That is what stops a stale or forged
   * result from extending a credential's life.
   *
   * The CCID is unchanged by renewal - see `ccid.ts`. Only the nonce and expiry move.
   */
  async renew(
    input: CredentialResultInput & { newExpiresAt: bigint; newNonce: bigint },
  ): Promise<{ ccid: Hex; hash: Hex }> {
    const ccid = computeCcid(input);
    const hash = await this.gateway.write.renewCredential(
      [
        toResultTuple(input, []),
        [...(input.destinations ?? [])],
        input.newExpiresAt,
        input.newNonce,
      ],
      this.writeOptions,
    );
    return { ccid, hash };
  }

  /**
   * Revoke, and propagate the revocation to `destinations`.
   *
   * `poolId` selects the policy whose revocation mode applies. Authority is scoped per
   * pool, because revocation authority is a property of the policy that admitted the
   * holder - not of the credential. Under `GovernanceOnly` the issuer is refused, which
   * is the point of that mode.
   *
   * Revocation is **terminal**: no route returns a revoked credential to `Valid`.
   */
  async revoke(
    ccid: Hex,
    options: { poolId: Hex; reason: Hex; destinations?: readonly bigint[] },
  ): Promise<Hex> {
    return this.gateway.write.revoke(
      [ccid, options.poolId, options.reason, [...(options.destinations ?? [])]],
      this.writeOptions,
    );
  }

  /** Suspend. Issuer-controlled, and reversible via {@link resume}. */
  async suspend(ccid: Hex, reason: Hex, destinations: readonly bigint[] = []): Promise<Hex> {
    return this.gateway.write.suspend([ccid, reason, [...destinations]], this.writeOptions);
  }

  /** Lift a suspension. Refused for a revoked credential - the state is terminal. */
  async resume(ccid: Hex, reason: Hex, destinations: readonly bigint[] = []): Promise<Hex> {
    return this.gateway.write.resume([ccid, reason, [...destinations]], this.writeOptions);
  }

  /**
   * Mark lapsed credentials `Expired` on chain, for each of `ccids`.
   *
   * Cosmetic as far as safety is concerned: the registry already denies an expired
   * credential from the moment `expiresAt` passes, without any keeper. It exists so
   * monitoring and audit exports see a clean terminal transition rather than a set of
   * `Valid` records that quietly lapsed.
   *
   * A system whose expiry depended on a sweeper being alive would **fail open** the
   * moment that sweeper stalled, which is the one unacceptable direction for a compliance
   * control.
   *
   * @returns The transaction hash. `expireDue` also returns the number of credentials it
   *   expired, but a state-changing call's return value is not observable from the
   *   transaction hash - use {@link simulateSweep} first if the count matters.
   *
   * Bounded by `MAX_SWEEP_BATCH` so one call cannot exceed block gas.
   */
  async sweepExpiries(ccids: readonly Hex[]): Promise<Hex> {
    return this.registry.write.expireDue([[...ccids]], this.writeOptions);
  }

  /**
   * How many credentials would {@link sweepExpiries} expire?
   *
   * Simulated rather than sent, so an operator can size a batch before committing to it.
   * The registry skips unknown CCIDs and already-`Expired` ones, so the count is the
   * number that would actually change.
   */
  async simulateSweep(ccids: readonly Hex[]): Promise<bigint> {
    const { result } = await this.registry.simulate.expireDue([[...ccids]], this.writeOptions);
    return result;
  }

  /** Max records per sweep. */
  async maxSweepBatch(): Promise<bigint> {
    return this.registry.read.MAX_SWEEP_BATCH();
  }
}

/** Convenience: the CCID a given input produces, without submitting anything. */
export function previewCcid(input: CcidInput): Hex {
  return computeCcid(input);
}

export { CredentialStatus, InvestorClass };
export type { CcidInput };
