/**
 * The buyer piece for `x402/exact/aptos`: the wallet builds and signs the scheme's own payment for the request's
 * option and answers `{transaction}`.
 */
import { walletBuiltPiece } from "./x402-account-rails.js";

const APTOS_ADDRESS = /^0x[0-9a-fA-F]{1,64}$/;

export const x402ExactAptos = walletBuiltPiece("x402/exact/aptos", ["aptos"], (a) => APTOS_ADDRESS.test(a), [
  "transaction",
]);
