/** The buyer piece for `mpp/charge/evm/authorization`: the token's EIP-712 name and version are the buyer's input. */
import { mppChargePiece } from "./mpp.js";

export const mppChargeEvmAuthorization = mppChargePiece("mpp/charge/evm/authorization", { tokenDomain: "object" });
