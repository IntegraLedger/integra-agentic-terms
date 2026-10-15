/**
 * The buyer piece for `x402/exact/sui`: the wallet builds the scheme's payment, adds the request's `pureInput` as the
 * one unused `Pure` input, bounds the expiration by epoch as the request asks, signs, and answers
 * `{signature, transaction}`. The epoch bound is this piece's choice, not a condition of the record: a signed
 * transaction without one that carries the hash completes, and is recorded.
 */
import { walletBuiltPiece } from "./x402-account-rails.js";

const SUI_ADDRESS = /^0x[0-9a-fA-F]{64}$/;

export const x402ExactSui = walletBuiltPiece("x402/exact/sui", ["sui"], (a) => SUI_ADDRESS.test(a), [
  "signature",
  "transaction",
]);
