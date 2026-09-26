/**
 * The buyer piece for `x402/exact/cardano`: the wallet builds the scheme's payment with a TTL, attaches the request's
 * `auxiliaryData` and its hash, signs without broadcasting, and answers `{transaction, nonce}`.
 */
import { walletBuiltPiece } from "./x402-account-rails.js";

const BECH32_ADDRESS = /^[a-z_]{1,83}1[02-9ac-hj-np-z]{6,}$/;

export const x402ExactCardano = walletBuiltPiece(
  "x402/exact/cardano",
  ["cardano", "cip34"],
  (a) => BECH32_ADDRESS.test(a),
  ["transaction", "nonce"],
);
