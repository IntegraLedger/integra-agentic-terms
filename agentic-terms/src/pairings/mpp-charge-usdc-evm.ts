/**
 * The buyer piece for `mpp/charge/usdc/evm`: the EIP-3009 authorization whose nonce is usdc's derivation over the
 * challenge; the token's EIP-712 name and version are the buyer's input.
 */
import { mppChargePiece } from "./mpp.js";

export const mppChargeUsdcEvm = mppChargePiece("mpp/charge/usdc/evm", { tokenDomain: "object" });
