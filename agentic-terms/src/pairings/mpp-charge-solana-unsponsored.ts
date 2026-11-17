/**
 * The buyer piece for `mpp/charge/solana/unsponsored`, a charge of MPP's `solana` method whose challenge does not set
 * `feePayer: true`: the payer is the message's fee payer and pays its fee. The rest is `mpp/charge/solana`'s: the
 * message whose one LCP memo is the request's `externalId`, signed by the payer as `solana-message`, and the build's
 * own `transaction` credential, which the seller's server broadcasts. The signer moves nothing: a `signature`
 * credential, one the payer's own client broadcast before presenting it, is never what this piece completes.
 */
import { solanaChargeInputs } from "./mpp-charge-solana.js";
import { completeWith, mppRailPiece, signature64 } from "./mpp-rails.js";
import { SOLANA_ADDRESS, withUnitPrice } from "./x402-exact-solana.js";

export const mppChargeSolanaUnsponsored = mppRailPiece({
  pairing: "mpp/charge/solana/unsponsored",
  namespace: "solana",
  address: SOLANA_ADDRESS,
  payer: "payer",
  now: false,
  inputs: solanaChargeInputs,
  revive: withUnitPrice,
  complete: completeWith(signature64),
});
