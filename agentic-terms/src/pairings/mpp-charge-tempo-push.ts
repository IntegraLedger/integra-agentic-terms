/**
 * The buyer piece for `mpp/charge/tempo/push`: the signer broadcasts and answers the hash with its landed receipt, held
 * under the payment's own `FETCHED` member, where `bound` reads it for the memo. The payment sent is the credential
 * without it. The signer moves the payment, so a decline keeps it. The build is the protocol package's: with splits,
 * its `tempo-calls` request holds one call per recipient.
 */
import type { Presented } from "../types.js";
import { broadcasts, withoutFetched } from "./common.js";
import { mppChoice, mppChoose, mppRequest, pushComplete } from "./mpp.js";

export const mppChargeTempoPush = Object.freeze({
  choose: mppChoose("mpp/charge/tempo/push", { clientId: "optional-string" }),
  choice: mppChoice,
  request: mppRequest,
  complete: pushComplete,
  moves: broadcasts,
  sent(signed: Presented): Presented {
    return withoutFetched(signed as object) as Presented;
  },
});
