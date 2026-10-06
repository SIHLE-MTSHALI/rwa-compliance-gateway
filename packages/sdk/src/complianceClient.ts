import type { Address, Hex, PublicClient, WalletClient, Chain } from "viem";
import { getContract } from "viem";

import { computeCcid, type CcidInput } from "./ccid.js";
import {
  CredentialStatus,
  Decision,
  InvestorClass,
  decisionName,
  isAllow,
  isReviewRequired,
  isPoolConfigurationReason,
  needsHolderAction,
  type ReasonLabel,
} from "./reasons.js";

/**
 * The read path an integrator uses: "may this holder access this pool?"
 *
 * ## Why there is a client rather than an ABI export
 *
 * The decision is a three-way outcome with a reason, and the reason is the product. An
 * integrator that receives a bare `bool` is one refactor away from treating
 * `ReviewRequired` as `true`, which would make a pool's review requirement
 * unenforceable - it would be configured and then silently ignored.
 *
 * So {AccessDecision} is returned instead, with {AccessDecision.isAllowed} as the only
 * correct way to ask the access question and the reason always present.
 */

/** ABI for the read surface. Hand-written and minimal: only what this client calls. */
export const COMPLIANCE_MODULE_ABI = [
  {
    type: "function",
    name: "evaluate",
    stateMutability: "view",
    inputs: [
      {
        name: "request",
        type: "tuple",
        components: [
          { name: "ccid", type: "bytes32" },
          { name: "poolId", type: "bytes32" },
          { name: "requestedAmount", type: "uint256" },
          { name: "currentAllocation", type: "uint256" },
        ],
      },
    ],
    outputs: [
      { name: "decision", type: "uint8" },
      { name: "reasonCode", type: "bytes32" },
    ],
  },
  {
    type: "function",
    name: "evaluateAndRecord",
    stateMutability: "nonpayable",
    inputs: [
      {
        name: "request",
        type: "tuple",
        components: [
          { name: "ccid", type: "bytes32" },
          { name: "poolId", type: "bytes32" },
          { name: "requestedAmount", type: "uint256" },
          { name: "currentAllocation", type: "uint256" },
        ],
      },
    ],
    outputs: [
      { name: "decision", type: "uint8" },
      { name: "reasonCode", type: "bytes32" },
    ],
  },
  {
    type: "function",
    name: "isCredentialEligible",
    stateMutability: "view",
    inputs: [{ name: "ccid", type: "bytes32" }],
    outputs: [{ type: "bool" }],
  },
  {
    type: "function",
    name: "describeReason",
    stateMutability: "view",
    inputs: [{ name: "reasonCode", type: "bytes32" }],
    outputs: [{ type: "string" }],
  },
  {
    type: "function",
    name: "describeStatus",
    stateMutability: "view",
    inputs: [{ name: "status", type: "uint8" }],
    outputs: [{ type: "string" }],
  },
  {
    type: "function",
    name: "describeInvestorClass",
    stateMutability: "view",
    inputs: [{ name: "cls", type: "uint8" }],
    outputs: [{ type: "string" }],
  },
] as const;

export const COMPLIANCE_REGISTRY_ABI = [
  {
    type: "function",
    name: "statusOf",
    stateMutability: "view",
    inputs: [{ name: "ccid", type: "bytes32" }],
    outputs: [{ name: "status", type: "uint8" }],
  },
  {
    type: "function",
    name: "exists",
    stateMutability: "view",
    inputs: [{ name: "ccid", type: "bytes32" }],
    outputs: [{ type: "bool" }],
  },
  {
    type: "function",
    name: "isValid",
    stateMutability: "view",
    inputs: [{ name: "ccid", type: "bytes32" }],
    outputs: [{ type: "bool" }],
  },
  {
    type: "function",
    name: "ageOf",
    stateMutability: "view",
    inputs: [{ name: "ccid", type: "bytes32" }],
    outputs: [{ name: "age", type: "uint64" }],
  },
  {
    type: "function",
    name: "getRecord",
    stateMutability: "view",
    inputs: [{ name: "ccid", type: "bytes32" }],
    outputs: [
      {
        name: "record",
        type: "tuple",
        components: [
          { name: "ccid", type: "bytes32" },
          { name: "credentialType", type: "bytes32" },
          { name: "providerId", type: "bytes32" },
          { name: "evidenceHash", type: "bytes32" },
          { name: "schemaVersion", type: "uint32" },
          { name: "jurisdictionCode", type: "uint16" },
          { name: "investorClass", type: "uint8" },
          { name: "status", type: "uint8" },
          { name: "issuedAt", type: "uint64" },
          { name: "expiresAt", type: "uint64" },
          { name: "updatedAt", type: "uint64" },
          { name: "nonce", type: "uint64" },
        ],
      },
    ],
  },
  {
    type: "function",
    name: "getPropagationState",
    stateMutability: "view",
    inputs: [{ name: "ccid", type: "bytes32" }],
    outputs: [
      {
        name: "state",
        type: "tuple",
        components: [
          { name: "isReplica", type: "bool" },
          { name: "sourceChainSelector", type: "uint64" },
          { name: "lastUpdatedAt", type: "uint64" },
          { name: "lastSourceNonce", type: "uint64" },
        ],
      },
    ],
  },
] as const;

export const PROVIDER_REGISTRY_ABI = [
  {
    type: "function",
    name: "getProviderStatus",
    stateMutability: "view",
    inputs: [{ name: "providerId", type: "bytes32" }],
    outputs: [{ name: "status", type: "uint8" }],
  },
  {
    type: "function",
    name: "backsExistingCredentials",
    stateMutability: "view",
    inputs: [{ name: "providerId", type: "bytes32" }],
    outputs: [{ type: "bool" }],
  },
  {
    type: "function",
    name: "supportsSchema",
    stateMutability: "view",
    inputs: [
      { name: "providerId", type: "bytes32" },
      { name: "credentialType", type: "bytes32" },
      { name: "schemaVersion", type: "uint32" },
    ],
    outputs: [{ type: "bool" }],
  },
] as const;

/** Provider operational states. Mirrors `ProviderRegistry.ProviderStatus`. */
export const ProviderStatus = {
  Unknown: 0,
  /** New providers start here: an adapter must be reviewed before it can influence a decision. */
  Paused: 1,
  Active: 2,
  /**
   * Wind-down. **Still backs existing credentials** - only new issuance is blocked.
   *
   * Collapsing this into `Paused` would invalidate every live credential during a routine
   * provider migration. That is a real failure mode, not a hypothetical one.
   */
  Deprecated: 3,
  /** Issued on compromise. Existing credentials are not trusted either. */
  Revoked: 4,
} as const;

export type ProviderStatus = (typeof ProviderStatus)[keyof typeof ProviderStatus];

export function providerStatusName(status: ProviderStatus): string {
  switch (status) {
    case ProviderStatus.Unknown:
      return "Unknown";
    case ProviderStatus.Paused:
      return "Paused";
    case ProviderStatus.Active:
      return "Active";
    case ProviderStatus.Deprecated:
      return "Deprecated";
    case ProviderStatus.Revoked:
      return "Revoked";
    default:
      return "Unrecognized";
  }
}

/** A credential as stored on chain. Contains no investor identity - see `docs/privacy-model.md`. */
export interface CredentialRecord {
  readonly ccid: Hex;
  readonly credentialType: Hex;
  readonly providerId: Hex;
  /** A commitment to provider evidence. Never the evidence itself. */
  readonly evidenceHash: Hex;
  readonly schemaVersion: number;
  /** ISO 3166-1 numeric. A country, not a person. */
  readonly jurisdictionCode: number;
  readonly investorClass: InvestorClass;
  readonly status: CredentialStatus;
  readonly issuedAt: bigint;
  readonly expiresAt: bigint;
  readonly updatedAt: bigint;
  /** The replay guard. Deliberately **not** part of `ccid` - see `ccid.ts`. */
  readonly nonce: bigint;
}

/** Where a replica came from, for a destination chain. */
export interface PropagationState {
  readonly isReplica: boolean;
  readonly sourceChainSelector: bigint;
  readonly lastUpdatedAt: bigint;
  readonly lastSourceNonce: bigint;
}

/** The result of an access check. The reason is always present; it is the product. */
export interface AccessDecision {
  readonly decision: Decision;
  readonly reasonCode: Hex;
  readonly reasonLabel: string;
  /**
   * True only for `Decision.Allow`.
   *
   * Provided so callers cannot accidentally read `decision === 0`, which is correct today
   * but couples them to the enum's ordering.
   */
  readonly isAllowed: boolean;
  /** True when a human must look before access is permitted. */
  readonly requiresReview: boolean;
  /**
   * True when the denial is about the pool rather than the holder's credential.
   *
   * Worth surfacing in a holder-facing message: telling someone to re-verify because
   * their pool has no active policy is both wrong and alarming.
   */
  readonly isPoolConfigurationIssue: boolean;
  /** True when the holder can act on this themselves. */
  readonly holderCanAct: boolean;
}

/** What a caller wants to know about access. */
export interface AccessRequest {
  readonly ccid: Hex;
  readonly poolId: Hex;
  /**
   * Units of the pool's accounting token, for the allocation cap. Zero skips the cap
   * check, which is how you ask a pure eligibility question.
   */
  readonly requestedAmount?: bigint;
  /**
   * What the holder already holds in this pool.
   *
   * Supplied by the caller rather than read from the registry, because allocation lives
   * in the pool's own accounting: duplicating it here would create two sources of truth
   * that drift. **The caller must supply this truthfully** - the cap is only as good as
   * this value. See `docs/audit-readiness.md`.
   */
  readonly currentAllocation?: bigint;
}

export interface ComplianceClientAddresses {
  readonly complianceModule: Address;
  readonly registry: Address;
  readonly providers: Address;
}

/**
 * Turn raw contract output into an {@link AccessDecision}.
 *
 * Pure and exported, because two paths need it - a read-only preview and a recorded
 * check - and they must classify identically. An integrator who previews with one client
 * and records with the other should not be able to observe a different answer.
 *
 * @param reasonLabel What the *chain* says the code means. Passed in rather than looked
 *   up from this package's own table, so a newer contract's codes are reported faithfully
 *   instead of being silently reinterpreted by an older SDK.
 */
export function classifyDecision(decision: Decision, reasonCode: Hex, reasonLabel: string): AccessDecision {
  return {
    decision,
    reasonCode,
    reasonLabel,
    isAllowed: isAllow(reasonLabel),
    requiresReview: isReviewRequired(reasonLabel),
    isPoolConfigurationIssue: isPoolConfigurationReason(reasonLabel),
    holderCanAct: needsHolderAction(reasonLabel),
  };
}

export interface ComplianceClientOptions {
  readonly addresses: ComplianceClientAddresses;
  readonly chain?: Chain;
}

/**
 * Contract handles are built by these factories rather than inline in the constructor.
 *
 * The reason is typing: annotating a class field as `ReturnType<typeof getContract>`
 * captures the *generic* signature and erases the ABI-specific `read`/`write` inference,
 * leaving every call site typed against `{ address, abi }`. Returning the instantiation
 * from a named function and using `ReturnType<typeof fn>` keeps the inference intact.
 */
function moduleContract(client: PublicClient, address: Address, chain?: Chain) {
  return getContract({ abi: COMPLIANCE_MODULE_ABI, address, client, ...(chain ? { chain } : {}) });
}

function registryContract(client: PublicClient, address: Address, chain?: Chain) {
  return getContract({ abi: COMPLIANCE_REGISTRY_ABI, address, client, ...(chain ? { chain } : {}) });
}

function providersContract(client: PublicClient, address: Address, chain?: Chain) {
  return getContract({ abi: PROVIDER_REGISTRY_ABI, address, client, ...(chain ? { chain } : {}) });
}

/**
 * Read-only client for the access decision and the credential records behind it.
 *
 * Stateless apart from its cached contract handles; safe to construct once and share.
 */
export class ComplianceClient {
  private readonly module: ReturnType<typeof moduleContract>;
  private readonly registry: ReturnType<typeof registryContract>;
  private readonly providers: ReturnType<typeof providersContract>;

  constructor(client: PublicClient, options: ComplianceClientOptions) {
    this.module = moduleContract(client, options.addresses.complianceModule, options.chain);
    this.registry = registryContract(client, options.addresses.registry, options.chain);
    this.providers = providersContract(client, options.addresses.providers, options.chain);
  }

  /**
   * Evaluate an access request. Pure: no state change, no event.
   *
   * Safe to `eth_call`, which is what makes a preview possible - an integrator can show
   * a holder what a decision would be without writing anything.
   */
  /**
   * Normalise an {@link AccessRequest} into the tuple the contract expects.
   *
   * Shared by the view and state-changing paths so they cannot diverge: a preview and a
   * recorded check must send byte-identical calldata, or an integrator would see one
   * decision and get another.
   */
  private toTuple(request: AccessRequest) {
    return {
      ccid: request.ccid,
      poolId: request.poolId,
      requestedAmount: request.requestedAmount ?? 0n,
      currentAllocation: request.currentAllocation ?? 0n,
    };
  }

  async evaluate(request: AccessRequest): Promise<AccessDecision> {
    const [decision, reasonCode] = await this._readEvaluate(request);
    return this.toAccessDecision(decision, reasonCode);
  }

  /**
   * Evaluate and record is deliberately **not** on this class.
   *
   * It is a transaction, so it needs a wallet and an account, and this class takes a
   * `PublicClient` precisely so a read-only caller cannot send one by accident. Pools that
   * want the decision written on chain use {@link AccessRecorder}.
   *
   * The classification logic is shared: {@link classifyDecision} is a pure function, so a
   * preview and a recorded check cannot drift.
   */

  /**
   * Read `evaluate` and narrow its two outputs.
   *
   * The `as unknown` is deliberate and confined to this one place. viem infers a single
   * `string` for this ABI's two named non-tuple outputs, which is plainly wrong - the
   * contract returns `(uint8, bytes32)` - and `noUncheckedIndexedAccess` would otherwise
   * widen every destructured element to `T | undefined` as well. Narrowing once, here,
   * beats casting `as number` / `as Hex` at a dozen call sites and hoping.
   */
  private async _readEvaluate(request: AccessRequest): Promise<[Decision, Hex]> {
    const raw = (await this.module.read.evaluate([this.toTuple(request)])) as unknown;
    const [decision, reasonCode] = raw as readonly [number, Hex];
    return [decision as Decision, reasonCode];
  }

  /**
   * Build an {@link AccessDecision} from raw contract output.
   *
   * Separate from the call sites so the two paths cannot drift - a preview and a recorded
   * check must classify identically, or an integrator would see one answer and get
   * another.
   */
  private async toAccessDecision(decision: Decision, reasonCode: Hex): Promise<AccessDecision> {
    // The chain is the authority on labels; an unrecognised code returns `UNRECOGNIZED`
    // rather than reverting, so a newer contract cannot break this SDK's logging.
    const reasonLabel = (await this.module.read.describeReason([reasonCode])) as string;
    return classifyDecision(decision, reasonCode, reasonLabel);
  }

  /** Human-readable decision name, for logs and UIs. */
  describeDecision(decision: Decision): string {
    return decisionName(decision);
  }

  /**
   * Is the credential itself in good standing?
   *
   * Deliberately **not** an access gate. It answers "is this credential valid", which
   * is what a holder-facing status view needs, and ignores pool policy, allocation, and
   * review requirements - because those are properties of the *request*, not of the
   * credential.
   */
  async isCredentialEligible(ccid: Hex): Promise<boolean> {
    return this.module.read.isCredentialEligible([ccid]);
  }

  /** Lifecycle status with lazy expiry applied. This is the one policy paths use. */
  async statusOf(ccid: Hex): Promise<CredentialStatus> {
    return (await this.registry.read.statusOf([ccid])) as CredentialStatus;
  }

  async exists(ccid: Hex): Promise<boolean> {
    return this.registry.read.exists([ccid]);
  }

  /** Seconds since the record was last written. `type(uint64).max` when absent. */
  async ageOf(ccid: Hex): Promise<bigint> {
    return this.registry.read.ageOf([ccid]);
  }

  async getRecord(ccid: Hex): Promise<CredentialRecord> {
    const r = await this.registry.read.getRecord([ccid]);
    return {
      ccid: r.ccid,
      credentialType: r.credentialType,
      providerId: r.providerId,
      evidenceHash: r.evidenceHash,
      schemaVersion: Number(r.schemaVersion),
      jurisdictionCode: Number(r.jurisdictionCode),
      investorClass: r.investorClass as InvestorClass,
      status: r.status as CredentialStatus,
      issuedAt: r.issuedAt,
      expiresAt: r.expiresAt,
      updatedAt: r.updatedAt,
      nonce: r.nonce,
    };
  }

  /**
   * Propagation state for a replica.
   *
   * On a destination chain, `isReplica` is how an integrator knows they are reading a
   * cache rather than local truth - which is what makes `STALE_DESTINATION` a meaningful
   * denial to surface.
   */
  async getPropagationState(ccid: Hex): Promise<PropagationState> {
    const s = await this.registry.read.getPropagationState([ccid]);
    return {
      isReplica: s.isReplica,
      sourceChainSelector: s.sourceChainSelector,
      lastUpdatedAt: s.lastUpdatedAt,
      lastSourceNonce: s.lastSourceNonce,
    };
  }

  /** Provider status. `Deprecated` still backs existing credentials. */
  async getProviderStatus(providerId: Hex): Promise<ProviderStatus> {
    return (await this.providers.read.getProviderStatus([providerId])) as ProviderStatus;
  }

  /** True when the provider still backs credentials that already exist. */
  async backsExistingCredentials(providerId: Hex): Promise<boolean> {
    return this.providers.read.backsExistingCredentials([providerId]);
  }

  /**
   * Derive the CCID for a credential and evaluate access in one step.
   *
   * The convenience an integrator actually wants at the call site, and the place where
   * a mismatch between this derivation and the contract's would surface as a
   * `NO_CREDENTIAL` denial rather than as a bug.
   */
  async evaluateForCredential(
    input: CcidInput & { poolId: Hex; requestedAmount?: bigint; currentAllocation?: bigint },
  ): Promise<AccessDecision> {
    // Built with a spread rather than field-by-field assignment, because
    // `AccessRequest` is readonly and `exactOptionalPropertyTypes` rejects an explicit
    // `undefined`. A missing amount means zero, which is also the value the contract
    // treats as "skip the cap check".
    return this.evaluate({
      ccid: computeCcid(input),
      poolId: input.poolId,
      ...(input.requestedAmount === undefined ? {} : { requestedAmount: input.requestedAmount }),
      ...(input.currentAllocation === undefined ? {} : { currentAllocation: input.currentAllocation }),
    });
  }
}

export type { ReasonLabel };

/**
 * Write path for integrators that want the access decision recorded on chain.
 *
 * Separate from {@link ComplianceClient} because recording is a transaction: it needs a
 * wallet, and it needs an account. Keeping it off the read-only client means a caller who
 * only wants to *ask* cannot send one.
 *
 * Only allows and review-required outcomes are recorded. **Denials are deliberately not
 * emitted**, because an emitted denial would let anyone inflate a holder's public denial
 * history by probing them repeatedly, and the caller already has the reason in its
 * return value. There is a permissioned path for a compliance officer to record a denial
 * they resolved; see `AuditTrail.recordDecision`.
 */
export class AccessRecorder {
  private readonly module: ReturnType<typeof moduleContract>;

  /**
   * Passed on every write. viem's contract writer requires explicit options rather than
   * defaulting to a client account, which is the behaviour wanted here: a recorded access
   * decision should never be sent from an account nobody chose.
   */
  private readonly writeOptions: { account: Address; chain: Chain | undefined };

  constructor(walletClient: WalletClient, complianceModuleAddress: Address, account: Address, chain?: Chain) {
    this.module = moduleContract(walletClient as unknown as PublicClient, complianceModuleAddress, chain);
    this.writeOptions = { account, chain };
  }

  /**
   * Evaluate and record.
   *
   * @returns The decision, including the reason - a recorded denial still returns normally
   *   to the caller. Only a chain-level reconfiguration stops the transaction.
   */
  async record(request: AccessRequest): Promise<AccessDecision> {
    // `as unknown` for the same reason as `_readEvaluate`: viem collapses this ABI's two
    // named non-tuple outputs into one inferred type, and the value is fixed by the ABI.
    const raw = (await this.module.write.evaluateAndRecord(
      [
        {
          ccid: request.ccid,
          poolId: request.poolId,
          requestedAmount: request.requestedAmount ?? 0n,
          currentAllocation: request.currentAllocation ?? 0n,
        },
      ],
      this.writeOptions,
    )) as unknown;
    const [decision, reasonCode] = raw as readonly [number, Hex];

    const reasonLabel = (await this.module.read.describeReason([reasonCode])) as string;
    return classifyDecision(decision as Decision, reasonCode, reasonLabel);
  }
}
