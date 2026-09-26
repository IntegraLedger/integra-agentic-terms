/**
 * The buyer piece for `x402/exact/sui`: the wallet builds the scheme's payment, adds the request's `pureInput` as the
 * one unused `Pure` input, bounds the expiration by epoch, signs, and answers `{signature, transaction}`.
 */
import { walletBuiltPiece } from "./x402-account-rails.js";

const SUI_ADDRESS = /^0x[0-9a-fA-F]{64}$/;

export const x402ExactSui = walletBuiltPiece("x402/exact/sui", ["sui"], (a) => SUI_ADDRESS.test(a), [
  "signature",
  "transaction",
]);
