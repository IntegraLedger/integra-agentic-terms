/** The buyer piece for `mpp/charge/evm/permit2`: the seller server's submitting address is the buyer's input. */
import { mppChargePiece } from "./mpp.js";

export const mppChargeEvmPermit2 = mppChargePiece("mpp/charge/evm/permit2", { spender: "string" });
