/**
 * The buyer piece for `x402/exact/eip155/gateway-batched`: Circle Gateway's batched payment, an EIP-3009
 * `TransferWithAuthorization` signed in the Gateway Wallet's `GatewayWalletBatched` domain with the ATR hash as its
 * nonce. The first option on the signer's chain; the choice carries `minValiditySeconds`, the minimum validity Circle
 * Gateway's `/supported` serves for the network, which the caller gives in `inputs` (the gate declines `floor-missing`
 * before it reads the offer where `inputs` lacks it). The typed data is handed to the signer exactly as built, and the
 * signature completes the payment, with the payment identifier where the challenge advertises it. The pairing is at
 * coverage `none`: its payment is taken only after an agreement on the same network.
 */
import type { Refusal } from "@integraledger/lcp/core";
import type { BuyerPiece, Chosen, Inputs, Read } from "../types.js";
import { firstOption, isRefusal, refuse, x402Chosen } from "./common.js";
import { evmX402Piece } from "./evm-x402.js";

const PAIRING = "x402/exact/eip155/gateway-batched";
const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const evm = evmX402Piece(PAIRING);

export const x402ExactEip155GatewayBatched: BuyerPiece = Object.freeze({
  ...evm,
  choose(read: Read, account: string, inputs: Inputs, now: number, ref: string): Chosen | Refusal {
    const o = firstOption(read, account, "eip155", PAIRING, EVM_ADDRESS);
    if (isRefusal(o)) return refuse("x402/no-payable-option");
    const served = inputs["minValiditySeconds"];
    return x402Chosen(
      PAIRING,
      { required: o.required, accepted: o.accepted, from: o.address, now, ...(served !== undefined ? { minValiditySeconds: served } : {}) },
      ref,
    );
  },
});
