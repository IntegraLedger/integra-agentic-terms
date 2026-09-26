import type { AtrHash, Binding as LcpBinding, Json, Presented as LcpPresented, Refusal } from "@integraledger/lcp";
import type { AptosUnsigned } from "@integraledger/lcp/aptos";
import type { AvmUnsigned } from "@integraledger/lcp/avm";
import type { TapUnsigned, ViUnsigned } from "@integraledger/lcp/card";
import type { CardanoUnsigned } from "@integraledger/lcp/cardano";
import type { CasperUnsigned } from "@integraledger/lcp/casper";
import type { CcdUnsigned } from "@integraledger/lcp/ccd";
import type { LnUnsigned } from "@integraledger/lcp/lightning";
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
import type { Unsigned as UcpUnsigned } from "@integraledger/lcp/ucp";
import type { Unsigned as Ap2Unsigned } from "@integraledger/lcp/ap2";
import type { Unsigned as AcpUnsigned } from "@integraledger/lcp/acp";
import type { X402Unsigned } from "@integraledger/lcp/x402";
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
 * scheme. The protocol-group results that carry no kind of their own are tagged here: the TAP field (`tap-field`), VI's
 * checkout mandate (`vi-checkout-mandate`), AP2's checkout-mandate content (`ap2-checkout-mandate`), the UCP checkout
 * for the buyer's mandate issuer (`ucp-checkout`) and ACP's allowance (`acp-allowance`). `batch` is several requests,
 * signed in order, as are the requests of an in-channel payment. `ed25519-raw` is raw Ed25519 over the bytes given.
 * `tempo-calls` is a Tempo charge with splits: the calls, in order, of one `0x76` transaction.
 */
export type SigningRequest =
  | Extract<X402Unsigned, unknown>["request"]
  | Extract<MppUnsigned, unknown>["request"]
  | UsdcUnsigned["request"]
  | SessionUnsigned["funding"]
  | RailSessionUnsigned["request"]
  | KeyAuthorizationUnsigned["request"]
  | SvmUnsigned["request"]
  | StellarUnsigned["request"]
  | XrplUnsigned<unknown>["request"]
  | HederaUnsigned["request"]
  | Extract<Awaited<ReturnType<(typeof exactHederaExecutor)["build"]>>, { request: unknown }>["request"]
  | AvmUnsigned["request"]
  | AptosUnsigned["request"]
  | CardanoUnsigned["request"]
  | SuiUnsigned["request"]
  | StarknetUnsigned["request"]
  | PolkadotUnsigned["request"]
  | TronUnsigned["request"]
  | TvmUnsigned["request"]
  | NearUnsigned["request"]
  | CasperUnsigned["request"]
  | CcdUnsigned["request"]
  | LnUnsigned["request"]
  | ({ kind: "tap-field" } & TapUnsigned)
  | ({ kind: "vi-checkout-mandate" } & ViUnsigned)
  | { kind: "ap2-checkout-mandate"; content: Ap2Unsigned["content"] }
  | { kind: "ucp-checkout"; checkout: UcpUnsigned["checkout"] }
  | { kind: "acp-allowance"; allowance: AcpUnsigned["allowance"] }
  | { kind: "batch"; requests: readonly (BatchRequest | WithinSigningRequest)[] }
  | Extract<BatchRequest, { kind: "ed25519-raw" }>
  | TempoCalls;

/** Several calls in one Tempo `0x76` transaction, in order, signed by the payer; broadcast by it where `broadcast`. */
export interface TempoCalls {
  kind: "tempo-calls";
  chainId: number;
  calls: readonly { to: `0x${string}`; data: `0x${string}` }[];
  validBefore: number;
  broadcast: boolean;
}

/**
 * The signer's answer, as JSON. Byte strings are `0x` hex. Each kind's form is its buyer piece's: a signature as hex
 * for the kinds whose payment takes one signature, an object for the kinds whose payment takes several values, and a
 * list, in order, for `batch`.
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

/** What the gate chose to pay, as plain JSON data, so `finish` can rebuild the same request. */
export interface Chosen {
  pairing: string;
  choice: Json;
  ref: string;
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
  | "agreement-failed";

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

/** `transact`'s optional members: the buyer's own chain values, and the signer that pays the agreement. */
export interface TransactOptions {
  readonly inputs?: Inputs | undefined;
  readonly agreementSigner?: Signer | undefined;
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
  /** The pairing's build over that input, for a binding whose `build` takes other arguments than the input and the hash. */
  build?(choice: unknown, h: AtrHash): Promise<unknown>;
  /** The request for the signer, or null where the build is itself the payment and nothing is signed. */
  request(unsigned: unknown): SigningRequest | null | Refusal;
  /**
   * The payment the answer completes, or, for a pairing signed in steps, the next request: the gate then calls the
   * signer again and passes every answer so far, in order, as a list.
   */
  complete(unsigned: unknown, signature: Signature, chosen: Chosen): Promise<Presented | Next | Refusal>;
  /** The payment as it is sent, once `bound` has read it, where the completion carries values only `bound` reads. */
  sent?(signed: Presented): Presented;
  /** True when the signer, handed this first request, moves the payment itself before the gate reads what was signed. */
  moves?(request: SigningRequest): boolean;
}

export type { AtrHash };
