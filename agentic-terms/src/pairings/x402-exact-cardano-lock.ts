/**
 * The buyer piece for `x402/exact/cardano/lock`, x402's two Cardano lock methods (`extra.assetTransferMethod`
 * `"masumi"` or `"script"`): a deposit into an escrow or a contract the seller defines, which is a charge and never an
 * agreement. The wallet builds the scheme's lock for the request's option with a TTL, which a lock must carry,
 * attaches the request's `auxiliaryData` and its hash, signs without broadcasting, and answers `{transaction, nonce}`.
 */
import { walletBuiltPiece } from "./x402-account-rails.js";

const BECH32_ADDRESS = /^[a-z_]{1,83}1[02-9ac-hj-np-z]{6,}$/;

export const x402ExactCardanoLock = walletBuiltPiece(
  "x402/exact/cardano/lock",
  ["cardano", "cip34"],
  (a) => BECH32_ADDRESS.test(a),
  ["transaction", "nonce"],
);
