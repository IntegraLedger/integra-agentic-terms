/**
 * The buyer piece for `mpp/charge/tempo/push`: the signer broadcasts and answers the hash with its landed receipt, which
 * `bound` reads for the memo. The payment sent is the credential without the landed receipt. The signer moves the
 * payment, so a decline keeps it. The build is the protocol package's: with splits, its `tempo-calls` request holds one
 * call per recipient.
 */
import type { MppCredential } from "@integraledger/lcp/mpp";
import type { Presented } from "../types.js";
import { broadcasts } from "./common.js";
import { mppChoice, mppChoose, mppRequest, pushComplete } from "./mpp.js";

export const mppChargeTempoPush = Object.freeze({
  choose: mppChoose("mpp/charge/tempo/push", { clientId: "optional-string" }),
  choice: mppChoice,
  request: mppRequest,
  complete: pushComplete,
  moves: broadcasts,
  sent(signed: Presented): Presented {
    const { landed: _landed, ...credential } = signed as MppCredential & { landed?: unknown };
    return credential;
  },
});
