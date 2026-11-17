/**
 * `tempo-call` requests (profile `buyer-gate.md`, rule 13): one call, `call.to` with `call.data`, that the payer's
 * wallet signs in a Tempo transaction on chain `chainId`, payable until `validBefore`. The summary is read only where
 * the call is a payment channel's `open` to the escrow `call.to` and nothing else, the call the protocol package's
 * Tempo session build writes: the TIP-20 channel reserve's
 * `open(address payee, address operator, address token, uint96 deposit, bytes32 salt, address authorizedSigner)` or the
 * earlier escrow's `open(address payee, address token, uint128 deposit, bytes32 salt, address authorizedSigner)`. Any
 * other call has no summary.
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

interface Open {
  payee: string;
  operator?: string;
  token: string;
  deposit: bigint;
  authorizedSigner: string;
}

/** The `open` call's members, each address in lowercase hex; undefined for any other data or a deposit out of range. */
function openOf(data: string): Open | undefined {
  const v2 = OPEN_V2.exec(data);
  if (v2 !== null) {
    const deposit = BigInt(`0x${v2[4]!}`);
    if (deposit >= 1n << 96n) return undefined;
    const operator = `0x${v2[2]!.toLowerCase()}`;
    return {
      payee: `0x${v2[1]!.toLowerCase()}`,
      ...(operator === ZERO ? {} : { operator }),
      token: `0x${v2[3]!.toLowerCase()}`,
      deposit,
      authorizedSigner: `0x${v2[6]!.toLowerCase()}`,
    };
  }
  const v1 = OPEN_V1.exec(data);
  if (v1 === null) return undefined;
  const deposit = BigInt(`0x${v1[3]!}`);
  if (deposit >= 1n << 128n) return undefined;
  return { payee: `0x${v1[1]!.toLowerCase()}`, token: `0x${v1[2]!.toLowerCase()}`, deposit, authorizedSigner: `0x${v1[5]!.toLowerCase()}` };
}

/**
 * `mpp/session/tempo`'s opening: the deposit moves from the payer to the escrow `call.to`, and the channel's payee may
 * draw on it with vouchers, which are signed apart, so the summary names no amount. The one payee is the `open`'s
 * payee, with the deposit; the asset its token; the network `eip155:` and `chainId`; the validity none to
 * `validBefore`, in seconds. `deposit` is the deposit, `operator` the TIP-20 channel reserve's operator where it is not
 * the zero address, and `grant` `{escrow, authorizedSigner}`: the contract that holds the deposit and the key the
 * `open` names to sign the channel's vouchers. Who may close the channel is the escrow's rule, which the call does not
 * state.
 */
export function tempoOpen(request: SigningRequest): Shown | undefined {
  const r = request as { kind?: unknown; chainId?: unknown; call?: unknown; validBefore?: unknown };
  // A call of any other member moves what this summary does not read.
  if (r.kind !== "tempo-call" || !isObject(r.call) || Object.keys(r.call).sort().join() !== "data,to") return undefined;
  const chain = decimal(r.chainId);
  const before = decimal(r.validBefore);
  const escrow = address(r.call["to"]);
  const data = r.call["data"];
  const open = typeof data === "string" ? openOf(data) : undefined;
  if (chain === undefined || before === undefined || before === "0" || escrow === undefined || open === undefined) return undefined;
  const deposit = open.deposit.toString();
  const grant: Json = { escrow, authorizedSigner: open.authorizedSigner };
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
