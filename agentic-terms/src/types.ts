import type { Act, AtrHash, Binding as LcpBinding, Json, Presented as LcpPresented, Refusal } from "@integraledger/lcp";
import type { AptosUnsigned } from "@integraledger/lcp/aptos";
import type { AvmUnsigned } from "@integraledger/lcp/avm";
import type { TapUnsigned, VicUnsigned, ViCheckoutUnsigned, ViUnsigned } from "@integraledger/lcp/card";
import type { CardanoUnsigned } from "@integraledger/lcp/cardano";
import type { CasperUnsigned } from "@integraledger/lcp/casper";
import type { CcdUnsigned } from "@integraledger/lcp/ccd";
import type { LnMppUnsigned } from "@integraledger/lcp/lightning";
import type { exactHederaExecutor, HederaUnsigned } from "@integraledger/lcp/hedera";
import type {
  MPP_BINDINGS,
  MppCredential,
  MppUnsigned,
  RailSessionUnsigned,
  SessionUnsigned,
  UsdcUnsigned,
  WithinSigningRequest,
} from "@integraledger/lcp/mpp";
import type { NearUnsigned } from "@integraledger/lcp/near";
import type { PolkadotUnsigned } from "@integraledger/lcp/polkadot";
import type { StarknetUnsigned } from "@integraledger/lcp/starknet";
import type { StellarUnsigned } from "@integraledger/lcp/stellar";
import type { SuiUnsigned } from "@integraledger/lcp/sui";
import type { KeyAuthorizationUnsigned } from "@integraledger/lcp/tempo";
import type { TronUnsigned } from "@integraledger/lcp/tron";
import type { TvmUnsigned } from "@integraledger/lcp/tvm";
import type { AgentSignedUnsigned, Checkout as UcpCheckout, Unsigned as UcpUnsigned } from "@integraledger/lcp/ucp";
import type { Unsigned as Ap2Unsigned } from "@integraledger/lcp/ap2";
import type { Unsigned as AcpUnsigned } from "@integraledger/lcp/acp";
import type { HttpRequest, PaymentRequired, PaymentRequirements, ToolCall, X402Unsigned } from "@integraledger/lcp/x402";
import type { SigningRequest as BatchRequest } from "@integraledger/lcp/x402-batch-settlement";
import type { SvmUnsigned } from "@integraledger/lcp/x402-exact-solana";
import type { XrplUnsigned } from "@integraledger/lcp/xrpl";

/** The largest ATR the gate fetches, hashes or checks: 1 MiB. */
export const MAX_ATR_BYTES = 1_048_576;

/** The pairing the caller names, as its binding. */
export type Binding = LcpBinding | (typeof MPP_BINDINGS)[number];
/** What the buyer presents as payment. */
export type Presented = LcpPresented | MppCredential;

/**
 * WHATWG fetch, or anything with its call shape. The caller's network policy (proxy, egress rules) lives here. The gate
 * asks with `redirect: "manual"` and reads a 3xx answer, or one of type `opaqueredirect`, as a redirect it does not
 * follow.
 */
export type Fetch = (
  url: string,
  init: { method: "GET"; redirect: "manual"; signal: AbortSignal; headers?: Record<string, string> },
) => Promise<Response>;

/**
 * What a signer is handed: the `request` of the pairing's `build` result, exactly as built, one kind per signing
 * scheme. The protocol-group results that carry no kind of their own are tagged here: the TAP field (`tap-field`), the
 * Visa Intelligent Commerce transaction reference (`vic-reference`), VI's checkout payload for the agent's `checkout_jwt`
 * (`vi-checkout`), VI's checkout mandate (`vi-checkout-mandate`), AP2's checkout-mandate content (`ap2-checkout-mandate`),
 * the UCP checkout for the buyer's mandate issuer (`ucp-checkout`), the `legal_context` member a UCP platform writes into
 * the request that completes the checkout, beside that checkout (`ucp-legal-context`), and ACP's allowance
 * (`acp-allowance`). `batch` is several requests, signed in order, as are the requests of an in-channel payment.
 * `ed25519-raw` is raw Ed25519 over the bytes given.
 * Where the wallet builds the transaction and picks its expiry itself (`aptos-transaction`, `cardano-transaction`,
 * `sui-transaction` and `substrate-call`), the gate adds the latest deadline the wallet may sign, the pairing's ceiling
 * in the form's own unit, as a decimal string: `maxExpirationTimestampSecs` (Unix seconds), `maxTtl` (a slot),
 * `maxEpoch` (an epoch) or `maxEraPeriod` (the longest mortal era, in blocks).
 */
export type SigningRequest =
  | Extract<X402Unsigned, unknown>["request"]
  | Extract<MppUnsigned, unknown>["request"]
  | UsdcUnsigned["request"]
  | SessionUnsigned["funding"]
  | Exclude<RailSessionUnsigned["request"], { kind: "hedera-session-open" }>
  | KeyAuthorizationUnsigned["request"]
  | SvmUnsigned["request"]
  | XrplUnsigned<unknown>["request"]
  | HederaUnsigned["request"]
  | Extract<Awaited<ReturnType<(typeof exactHederaExecutor)["build"]>>, { request: unknown }>["request"]
  | AvmUnsigned["request"]
  | (AptosUnsigned["request"] & { readonly maxExpirationTimestampSecs?: string })
  | (CardanoUnsigned["request"] & { readonly maxTtl?: string })
  | (SuiUnsigned["request"] & { readonly maxEpoch?: string })
  | StarknetUnsigned["request"]
  | StellarUnsigned["request"]
  | (PolkadotUnsigned["request"] & { readonly maxEraPeriod?: string })
  | TronUnsigned["request"]
  | TvmUnsigned["request"]
  | NearUnsigned["request"]
  | CasperUnsigned["request"]
  | CcdUnsigned["request"]
  | LnMppUnsigned["request"]
  | ({ kind: "tap-field" } & TapUnsigned)
  | ({ kind: "vi-checkout-mandate" } & ViUnsigned)
  | ({ kind: "vic-reference" } & VicUnsigned)
  | ({ kind: "vi-checkout" } & ViCheckoutUnsigned)
  | { kind: "ap2-checkout-mandate"; content: Ap2Unsigned["content"] }
  | { kind: "ucp-checkout"; checkout: UcpUnsigned["checkout"] }
  | { kind: "ucp-legal-context"; checkout: UcpCheckout; legal_context: AgentSignedUnsigned["legal_context"] }
  | { kind: "acp-allowance"; allowance: AcpUnsigned["allowance"] }
  | { kind: "batch"; requests: readonly (BatchRequest | WithinSigningRequest)[] }
  | Extract<BatchRequest, { kind: "ed25519-raw" }>;

/**
 * The signer's answer, as JSON. Each kind's form is its buyer piece's: a signature for the kinds whose payment takes one
 * signature, an object for the kinds whose payment takes several values, and a list, in order, for `batch`. Byte strings
 * are `0x` hex, except where the signers guide names another form for the kind: base58, base64, or hex digits without
 * `0x`.
 */
export type Signature = Json;

export interface Signer {
  /** The payer, CAIP-10: `eip155:84532:0xf39F…2266`. */
  readonly account: string;
  /** Signs exactly `request`. */
  sign(request: SigningRequest): Promise<Signature>;
}

/** The buyer's own values a pairing's build needs beside the offer, such as a recent block or an account nonce. */
export type Inputs = { readonly [k: string]: Json };

/**
 * What the gate chose to pay, as plain JSON data, so `finish` can rebuild the same request. `agreement` is the agreement
 * URL the seller's offer names, for a pairing at coverage `none`, whose payment is not itself a public proof of the ATR
 * hash.
 */
export interface Chosen {
  pairing: string;
  choice: Json;
  ref: string;
  agreement?: string;
  /**
   * For a form whose wallet picks the expiry, the latest deadline the request handed to it carries, as a decimal string
   * in the form's unit, so that a rebuild gives the request the signer was handed and the signed deadline is held to it.
   */
  deadline?: string;
}

export type DeclineCode =
  | "pairing-not-supported"
  | "offer-unreadable"
  | "no-payable-option"
  | "link-not-https"
  | "atr-unfetchable"
  | "atr-too-large"
  | "hash-mismatch"
  | "signer-failed"
  | "signed-not-bound"
  | "agreement-not-offered"
  | "agreement-pending"
  | "agreement-failed"
  | "not-approved"
  | "atr-malformed"
  | "option-not-in-atr"
  | "request-mismatch"
  | "summary-missing"
  | "past-ceiling"
  | "no-end"
  | "floor-missing";

export interface Reason {
  readonly code: DeclineCode;
  readonly detail: string;
}

/**
 * A decline. `moved` is present when the signer moved the payment before the decline: the payment as signed, in the
 * protocol's own form, with the ATR bytes and their hash, for the buyer to keep and present again.
 */
export type Declined = {
  readonly decline: Reason;
  readonly moved?: { readonly signed: unknown; readonly bytes: Uint8Array; readonly h: AtrHash };
};

/**
 * The request the buyer is about to pay, the one the seller's offer answered, in the form the protocol package's request
 * commitment reads it: over HTTP `{method, target, body, headers?}`, over MCP the tool call `{name, arguments?}`.
 */
export type ResourceRequest = HttpRequest | ToolCall;

/**
 * The raised ceilings: a pairing id mapped to a positive safe integer of seconds, the longest a signed payment through it
 * may stay payable, or to `"no-end"`, which lifts the pairing's ceiling and admits a form that signs no end.
 */
export type Ceilings = { readonly [pairing: string]: number | "no-end" };

/** Which signing of a payment the approver is asked about: `index`, from 0, of `count` signings. */
export interface SigningStep {
  readonly index: number;
  readonly count: number;
}

/** A payee of the summary: its account as the form names it, and its part of the amount or of the maximum. */
export interface Payee {
  readonly account: string;
  readonly amount: string;
}

/**
 * From and until when the signed payment is payable, each `null` where the form signs none, in `unit`: `"seconds"` for
 * Unix seconds, or a chain's own unit (a round, a slot, a block, a ledger or an epoch).
 */
export interface Validity {
  readonly notBefore: string | null;
  readonly notAfter: string | null;
  readonly unit: string;
}

/**
 * Every authority the signature grants, read from the request handed to the signer. Each integer is a decimal string,
 * each amount in the asset's base units, each time in Unix seconds but a `validity` whose `unit` names another. A
 * member the form does not have is absent; `payees`, `asset`, `network`, `validity` and `atr` are always present.
 */
export interface Summary {
  readonly amount?: string;
  readonly maximum?: string;
  readonly payees: readonly Payee[];
  readonly period?: string;
  readonly limitPerPeriod?: string;
  readonly end?: string;
  readonly operator?: string;
  readonly authorizationExpiry?: string;
  readonly refundExpiry?: string;
  readonly deposit?: string;
  readonly closableBy?: readonly string[];
  readonly grant?: Json;
  readonly asset: string;
  /** The CAIP-2 network, or null where the payment moves on no ledger (a card network, a fiat checkout). */
  readonly network: string | null;
  readonly validity: Validity;
  /** The ATR's bytes: the bytes the gate hashed, parsed and compared. */
  readonly atr: Uint8Array;
}

/** What the approver is asked about, once for each signing, before the signer is called for it. */
export interface ToSign {
  /** `"payment"`, the payment for the resource, or `"agreement"`, the agreement payment. */
  readonly act: "payment" | "agreement";
  /** The id of the pairing whose build made the request. */
  readonly pairing: string;
  /** The request the signer will be handed, as the signer is handed it. */
  readonly request: SigningRequest;
  readonly summary: Summary;
  readonly step: SigningStep;
}

/**
 * The approval callback `transact` requires. It answers `true`, or a promise of it, to approve the signing; any other
 * answer, a throw or a rejection approves nothing.
 */
export type Approver = (toSign: ToSign) => boolean | Promise<boolean>;

/**
 * `transact`'s options: the approval callback and the buyer's own request, required; the buyer's own chain values and
 * the floor inputs a rail's service serves; the raised ceilings; the first response's return value; the signer that
 * pays the agreement; the agreement payment the agent approved, exactly as `transact` or `agree` returned it in
 * `approve`; and a signal that ends the agreement exchange.
 */
export interface TransactOptions {
  readonly approver: Approver;
  readonly resourceRequest: ResourceRequest;
  readonly inputs?: Inputs | undefined;
  readonly ceilings?: Ceilings | undefined;
  readonly legalContext?: string | undefined;
  readonly agreementSigner?: Signer | undefined;
  readonly approved?: AgreementPayment | undefined;
  readonly signal?: AbortSignal | undefined;
  /**
   * The payment chosen, as `confirm` returned it in `chosen`, unchanged: `transact` builds that exact request, the one
   * the approver approved, rather than choosing anew with its clock and a new reference.
   */
  readonly chosen?: Chosen | undefined;
}

/** `confirm`'s options: the buyer's own request, required; its chain values and floor inputs; the raised ceilings. */
export interface ConfirmOptions {
  readonly resourceRequest: ResourceRequest;
  readonly inputs?: Inputs | undefined;
  readonly ceilings?: Ceilings | undefined;
}

/** `finish`'s options: the raised ceilings, which a later step's request is held to. */
export interface FinishOptions {
  readonly ceilings?: Ceilings | undefined;
}

/**
 * What `transact` returns once it has paid the agreement of a pairing paid after its agreement: the agreement's receipt;
 * the `Legal-Context` value the caller sends when it repeats its request; the charge chosen, `<slot>/<i>`; the ATR's
 * bytes the gate compared; and H, their SHA-256.
 */
export interface ToReturn {
  readonly agreement: AgreementReceipt;
  readonly legalContext: string;
  readonly charge: string;
  readonly bytes: Uint8Array;
  readonly h: AtrHash;
  /** Never present: no charge is signed before the return. */
  readonly signed?: never;
  /** Never present. */
  readonly landed?: never;
}

/**
 * `agree`'s optional members: the agreement payment the agent approved, exactly as it was returned in `approve`; the
 * buyer's own chain values; a signal that ends the exchange; and the charge the agreement is for, as `confirm` returned
 * it in `chosen`, so that only an agreement option its pairing's `agreementOn` admits is paid.
 */
export interface AgreeOptions {
  readonly approved?: AgreementPayment | undefined;
  readonly inputs?: Inputs | undefined;
  readonly signal?: AbortSignal | undefined;
  readonly chosen?: Chosen | undefined;
}

/** The next request of a pairing signed in steps. */
export interface Next {
  readonly next: SigningRequest;
}

/** What a binding's `read` gives the gate. */
export interface Read {
  h: AtrHash;
  link: string;
  offer?: unknown;
}

/**
 * The agreement payment, for the buyer's agent to approve before anything is signed: the agreement URL; `option`, the
 * option of the agreement URL's payment request that the gate pays, whose `amount`, `asset`, `payTo` and `network` are
 * the terms the agent approves; and `required`, that payment request as the agreement URL served it.
 */
export interface AgreementPayment {
  readonly url: string;
  readonly option: PaymentRequirements;
  readonly required: PaymentRequired;
}

/** An agreement payment the agent approves before it is signed, with the ATR bytes the gate compared and their hash. */
export interface ToApprove {
  readonly approve: AgreementPayment;
  readonly bytes: Uint8Array;
  readonly h: AtrHash;
}

/** The agreement resource's answer once the agreement payment carrying the ATR hash is recorded. */
export interface AgreementReceipt {
  atrHash: AtrHash;
  agreed: true;
  network: string;
  transaction: string;
}

/** Which option to pay, chosen from the read, the account, the buyer's inputs, the clock and the payment's `ref`. */
export type Choose = (read: Read, account: string, inputs: Inputs, now: number, ref: string, doc: unknown) => Chosen | Refusal;

/**
 * One pairing's buyer piece: which option to pay, the build input it revives from `Chosen`, what the signer is handed,
 * and how the signer's answer completes the payment.
 */
export interface BuyerPiece {
  /** `doc` is the seller's document as given, for pairings whose build takes it (card). */
  choose(...args: Parameters<Choose>): ReturnType<Choose> | Promise<ReturnType<Choose>>;
  /** The build's input, from `chosen` and, where the build reads the ATR itself, the bytes the gate compared. */
  choice(chosen: Chosen, bytes: Uint8Array): unknown;
  /**
   * The pairing's build over that input, for a binding whose `build` takes other arguments than the input, the hash and
   * the act.
   */
  build?(choice: unknown, h: AtrHash, act: Act): Promise<unknown>;
  /** The request for the signer, or null where the build is itself the payment and nothing is signed. */
  request(unsigned: unknown): SigningRequest | null | Refusal;
  /**
   * The payment the answer completes, or, for a pairing signed in steps, the next request: the gate then calls the
   * signer again and passes every answer so far, in order, as a list.
   */
  complete(unsigned: unknown, signature: Signature, chosen: Chosen): Promise<Presented | Next | Refusal>;
  /**
   * `chosen` with what the build drew itself, such as a random value, so that a rebuild from it gives the request the
   * signer was handed. Absent where the build is a function of the choice and the hash alone.
   */
  kept?(chosen: Chosen, unsigned: unknown): Chosen;
  /** The payment as it is sent, once `bound` has read it, where the completion carries values only `bound` reads. */
  sent?(signed: Presented): Presented;
  /** True when the signer, handed this first request, moves the payment itself before the gate reads what was signed. */
  moves?(request: SigningRequest): boolean;
  /**
   * True when the signer's answer shows that its side moved the payment itself, where the request cannot tell: AP2's
   * push funding, whose answer carries the receipt of the funds it sent.
   */
  movedBy?(signature: Signature): boolean;
}

export type { AtrHash };
