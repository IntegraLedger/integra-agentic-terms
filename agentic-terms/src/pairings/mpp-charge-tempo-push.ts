/**
 * The buyer piece for `mpp/charge/tempo/push`: the signer broadcasts and answers the hash with its landed receipt, which
 * `bound` reads for the memo. The payment sent is the credential without the landed receipt. The signer moves the
 * payment, so a decline keeps it. With splits, the
 * transaction carries one call per recipient.
 */
import { tempoPush, type MppCredential } from "@integraledger/lcp/mpp";
import type { Presented } from "../types.js";
import { broadcasts } from "./common.js";
import { acceptSplits, mppChoice, mppChoose, mppRequest, pushComplete, tempoBuild } from "./mpp.js";

export const mppChargeTempoPush = Object.freeze({
  choose: mppChoose("mpp/charge/tempo/push", { clientId: "optional-string" }, acceptSplits),
  choice: mppChoice,
  build: tempoBuild(tempoPush),
  request: mppRequest,
  complete: pushComplete,
  moves: broadcasts,
  sent(signed: Presented): Presented {
    const { landed: _landed, ...credential } = signed as MppCredential & { landed?: unknown };
    return credential;
  },
});
