/** The buyer piece for `mpp/charge/evm/hash`: the signer broadcasts the call and answers its transaction hash. */
import { mppChargePiece } from "./mpp.js";

export const mppChargeEvmHash = mppChargePiece("mpp/charge/evm/hash", {});
