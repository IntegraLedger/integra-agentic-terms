/**
 * The buyer piece for `spend-permissions/eip155`: the account's approval of a Spend Permission whose `salt` is H, the
 * sale's agreement and never a charge (lcp profile `spend-permissions-eip155.md`). The offer is the `402` body's
 * `spendPermission` on the account's network; the protocol package's build adds the account and gives the permission,
 * its typed data and its `approve` call. On the route `"signature"`, which the piece takes wherever the offer accepts
 * it, the signer is handed the typed data as `eip712` and answers the account's signature; on the route
 * `"transaction"` it is handed the `approve` call as `evm-call` with `broadcast` true, makes that call from the account
 * itself and answers the hash of the transaction that carried it, so a decline after it keeps what was sent as `moved`.
 * The payment is the return the `Spend-Permission` header carries, in the form the protocol package's
 * `encodeSpendPermissionHeader` writes.
 */
import type { AtrHash, Refusal } from "@integraledger/lcp/core";
import {
  decodeSpendPermissionHeader,
  encodeSpendPermissionHeader,
  spendPermissionsEip155,
  type SpendPermissionOffer,
  type SpendPermissionReturn,
  type SpendPermissionRoute,
  type SpendPermissionUnsigned,
} from "@integraledger/lcp/spend-permissions";
import type { BuyerPiece, Chosen, Presented, Read, Signature, SigningRequest } from "../types.js";
import { accountOf, broadcasts, choiceOf, isObject, isRefusal, refuse } from "./common.js";

const PAIRING = "spend-permissions/eip155";
const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;

/** The build's result with the route chosen, which the request is handed by. */
interface Built {
  readonly route: SpendPermissionRoute;
  readonly unsigned: SpendPermissionUnsigned;
}

function isBuilt(v: unknown): v is Built {
  return isObject(v) && (v["route"] === "signature" || v["route"] === "transaction") && isObject(v["unsigned"]);
}

export const spendPermissionsEip155Piece: BuyerPiece = Object.freeze({
  /** The offer on the account's network, by the route `"signature"` where it accepts it, else `"transaction"`. */
  choose(read: Read, account: string, _inputs: unknown, _now: number, ref: string): Chosen | Refusal {
    const a = accountOf(account);
    const offer = read.offer;
    if (a === undefined || a.namespace !== "eip155" || !EVM_ADDRESS.test(a.address) || !isObject(offer)) {
      return refuse("spend-permissions/no-payable-option");
    }
    const accepts: unknown = offer["accepts"];
    const route = !Array.isArray(accepts)
      ? undefined
      : accepts.includes("signature")
        ? "signature"
        : accepts.includes("transaction")
          ? "transaction"
          : undefined;
    if (offer["network"] !== a.network || route === undefined) return refuse("spend-permissions/no-payable-option");
    return { pairing: PAIRING, choice: { offer: offer as never, account: a.address, route }, ref };
  },
  choice: (chosen: Chosen) => choiceOf(chosen) ?? refuse("spend-permissions/choice-malformed"),
  /** The protocol package's build over the offer and the account, with the route chosen beside it. */
  async build(choice: unknown, h: AtrHash): Promise<Built | Refusal> {
    const c = isObject(choice) ? choice : {};
    const route = c["route"];
    if (route !== "signature" && route !== "transaction") return refuse("spend-permissions/choice-malformed");
    const unsigned = await spendPermissionsEip155.build({ offer: c["offer"] as SpendPermissionOffer, account: c["account"] as never }, h);
    return isRefusal(unsigned) ? unsigned : { route, unsigned };
  },
  /** The typed data the account signs, or the `approve` call it makes on the manager's network, exactly as built. */
  request(built: unknown): SigningRequest | Refusal {
    if (!isBuilt(built)) return refuse("spend-permissions/choice-malformed");
    const { typedData, approve } = built.unsigned;
    if (built.route === "signature") return { kind: "eip712", typedData };
    return { kind: "evm-call", chainId: typedData.domain.chainId, call: { to: approve.to, data: approve.data }, broadcast: true };
  },
  /**
   * The return: the offer's network and manager, the whole permission as built, and the signer's answer as the
   * signature or as the hash of the transaction that carried the approval; a value the return does not take is refused
   * with the code the protocol package's header gives it.
   */
  async complete(built: unknown, signature: Signature, chosen: Chosen): Promise<Presented | Refusal> {
    const offer = choiceOf(chosen)?.["offer"];
    if (!isBuilt(built) || !isObject(offer)) return refuse("spend-permissions/choice-malformed");
    const base = { network: offer["network"], manager: offer["manager"], permission: built.unsigned.permission };
    const header = encodeSpendPermissionHeader({ ...base, [built.route]: signature } as unknown as SpendPermissionReturn);
    return isRefusal(header) ? header : decodeSpendPermissionHeader(header);
  },
  /** The route `"transaction"`: the signer makes the call from the account before the gate reads what it answers. */
  moves: (request: SigningRequest) => broadcasts(request),
});
