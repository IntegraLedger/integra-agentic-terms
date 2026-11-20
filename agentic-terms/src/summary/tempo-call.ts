/**
 * `tempo-call` requests (profile `buyer-gate.md`, rule 13): one call, `call.to` with `call.data`, that the payer's
 * wallet signs in a Tempo transaction on chain `chainId`, payable until `validBefore`. The summary is read only where
 * the call is a payment channel's `open` to the escrow `call.to` and nothing else, the call the protocol package's
 * Tempo session build writes: the TIP-20 channel reserve's
 * `open(address payee, address operator, address token, uint96 deposit, bytes32 salt, address authorizedSigner)` or the
 * earlier escrow's `open(address payee, address token, uint128 deposit, bytes32 salt, address authorizedSigner)`. Any
 * other call has no summary. Before the earlier escrow's `open` the request may hold `approve`, `{to, data}`, the
 * currency's `approve(address spender, uint256 amount)`, the wallet's first call, which the escrow's `transferFrom` of
 * the deposit needs; it is read only where its token is the `open`'s, its spender the escrow and its amount at most the
 * deposit.
 */
import type { Json } from "@integraledger/lcp/core";
import type { Shown } from "../summary.js";
import type { SigningRequest } from "../types.js";
import { address, decimal, isObject } from "./evm-fields.js";

const ADDRESS_WORD = "0{24}([0-9a-fA-F]{40})";
const WORD = "([0-9a-fA-F]{64})";
/** The TIP-20 channel reserve's `open`: selector `0xedc53b00`, then payee, operator, token, deposit, salt, authorizedSigner. */
const OPEN_V2 = new RegExp(`^0x(?:edc53b00)${ADDRESS_WORD}${ADDRESS_WORD}${ADDRESS_WORD}${WORD}${WORD}${ADDRESS_WORD}$`, "i");
/** The earlier escrow's `open`: selector `0xc79ea485`, then payee, token, deposit, salt, authorizedSigner. */
const OPEN_V1 = new RegExp(`^0x(?:c79ea485)${ADDRESS_WORD}${ADDRESS_WORD}${WORD}${WORD}${ADDRESS_WORD}$`, "i");
const ZERO = "0x0000000000000000000000000000000000000000";
/** A token's `approve(address spender, uint256 amount)`: selector `0x095ea7b3`, then spender and amount. */
const APPROVE = new RegExp(`^0x(?:095ea7b3)${ADDRESS_WORD}${WORD}$`, "i");

export interface Open {
  /** `v2`, the TIP-20 channel reserve's `open`, or `v1`, the earlier escrow's. */
  version: "v1" | "v2";
  payee: string;
  operator?: string;
  token: string;
  deposit: bigint;
  salt: string;
  authorizedSigner: string;
}

/** The `open` call's members, each address in lowercase hex; undefined for any other data or a deposit out of range. */
export function openOf(data: string): Open | undefined {
  const v2 = OPEN_V2.exec(data);
  if (v2 !== null) {
    const deposit = BigInt(`0x${v2[4]!}`);
    if (deposit >= 1n << 96n) return undefined;
    const operator = `0x${v2[2]!.toLowerCase()}`;
    return {
      version: "v2",
      payee: `0x${v2[1]!.toLowerCase()}`,
      ...(operator === ZERO ? {} : { operator }),
      token: `0x${v2[3]!.toLowerCase()}`,
      deposit,
      salt: `0x${v2[5]!.toLowerCase()}`,
      authorizedSigner: `0x${v2[6]!.toLowerCase()}`,
    };
  }
  const v1 = OPEN_V1.exec(data);
  if (v1 === null) return undefined;
  const deposit = BigInt(`0x${v1[3]!}`);
  if (deposit >= 1n << 128n) return undefined;
  return {
    version: "v1",
    payee: `0x${v1[1]!.toLowerCase()}`,
    token: `0x${v1[2]!.toLowerCase()}`,
    deposit,
    salt: `0x${v1[4]!.toLowerCase()}`,
    authorizedSigner: `0x${v1[5]!.toLowerCase()}`,
  };
}

/**
 * The allowance a v1 opening's `approve` grants, `{token, spender, amount}`, each address in lowercase hex: undefined
 * where `approve` is not `{to, data}` of that call, or its token is not the `open`'s, its spender not the escrow, or its
 * amount more than the deposit. An allowance past the deposit, or to another spender, lets an account other than the
 * channel draw the payer's tokens.
 */
function allowanceOf(approve: unknown, open: Open, escrow: string): Json | undefined {
  if (!isObject(approve) || Object.keys(approve).sort().join() !== "data,to") return undefined;
  const token = address(approve["to"]);
  const data = approve["data"];
  const a = typeof data === "string" ? APPROVE.exec(data) : null;
  if (token === undefined || a === null) return undefined;
  const spender = `0x${a[1]!.toLowerCase()}`;
  const amount = BigInt(`0x${a[2]!}`);
  if (token.toLowerCase() !== open.token || spender !== escrow.toLowerCase() || amount > open.deposit) return undefined;
  return { token: open.token, spender, amount: amount.toString() };
}

/**
 * `mpp/session/tempo`'s opening: the deposit moves from the payer to the escrow `call.to`, and the channel's payee may
 * draw on it with vouchers, which are signed apart, so the summary names no amount. The one payee is the `open`'s
 * payee, with the deposit; the asset its token; the network `eip155:` and `chainId`; the validity none to
 * `validBefore`, in seconds. `deposit` is the deposit, `operator` the TIP-20 channel reserve's operator where it is not
 * the zero address, and `grant` `{escrow, authorizedSigner}`: the contract that holds the deposit and the key the
 * `open` names to sign the channel's vouchers, with `approve`, the allowance a v1 opening's `approve` grants, where the
 * request holds one; a request holding one beside the TIP-20 channel reserve's `open`, which takes no allowance, has no
 * summary. Who may close the channel is the escrow's rule, which the call does not state.
 */
export function tempoOpen(request: SigningRequest): Shown | undefined {
  const r = request as { kind?: unknown; chainId?: unknown; approve?: unknown; call?: unknown; validBefore?: unknown };
  // A call of any other member moves what this summary does not read.
  if (r.kind !== "tempo-call" || !isObject(r.call) || Object.keys(r.call).sort().join() !== "data,to") return undefined;
  const chain = decimal(r.chainId);
  const before = decimal(r.validBefore);
  const escrow = address(r.call["to"]);
  const data = r.call["data"];
  const open = typeof data === "string" ? openOf(data) : undefined;
  if (chain === undefined || before === undefined || before === "0" || escrow === undefined || open === undefined) return undefined;
  const allowance = r.approve === undefined ? undefined : open.version === "v1" ? allowanceOf(r.approve, open, escrow) : undefined;
  if (r.approve !== undefined && allowance === undefined) return undefined;
  const deposit = open.deposit.toString();
  const grant: Json = { escrow, authorizedSigner: open.authorizedSigner, ...(allowance === undefined ? {} : { approve: allowance }) };
  return {
    payees: [{ account: open.payee, amount: deposit }],
    asset: open.token,
    network: `eip155:${chain}`,
    validity: { notBefore: null, notAfter: before, unit: "seconds" },
    deposit,
    ...(open.operator === undefined ? {} : { operator: open.operator }),
    grant,
  };
}
