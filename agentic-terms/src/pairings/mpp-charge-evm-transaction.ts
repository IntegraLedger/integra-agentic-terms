/** The buyer piece for `mpp/charge/evm/transaction`: the answer is the signed EIP-1559 transaction of the call. */
import { mppChargePiece } from "./mpp.js";

export const mppChargeEvmTransaction = mppChargePiece("mpp/charge/evm/transaction", {});
