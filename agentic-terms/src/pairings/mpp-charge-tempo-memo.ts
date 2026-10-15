/**
 * The buyer piece for `mpp/charge/tempo/memo`: the answer is the signed `0x76` transaction; `clientId` is optional.
 * The build is the protocol package's: with splits, its `tempo-calls` request holds one call per recipient.
 */
import { mppChargePiece } from "./mpp.js";

export const mppChargeTempoMemo = mppChargePiece("mpp/charge/tempo/memo", { clientId: "optional-string" });
