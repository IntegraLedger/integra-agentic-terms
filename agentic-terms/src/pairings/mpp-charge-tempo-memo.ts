/**
 * The buyer piece for `mpp/charge/tempo/memo`: the answer is the signed `0x76` transaction; `clientId` is optional.
 * With splits, the transaction carries one call per recipient.
 */
import { tempoMemo } from "@integraledger/lcp/mpp";
import { acceptSplits, mppChargePiece, tempoBuild } from "./mpp.js";

export const mppChargeTempoMemo = Object.freeze({
  ...mppChargePiece("mpp/charge/tempo/memo", { clientId: "optional-string" }, acceptSplits),
  build: tempoBuild(tempoMemo),
});
