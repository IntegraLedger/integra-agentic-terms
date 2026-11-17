"""The buyer piece for spend-permissions/eip155, the account's approval of a Spend Permission whose salt is H, the sale's
agreement and never a charge. The offer is the 402 body's spendPermission on the account's network; the binding's build
adds the account and gives the permission, its typed data and its approve call. On the route "signature", which the
piece takes wherever the offer accepts it, the signer is handed the typed data as eip712 and answers the account's
signature; on the route "transaction" it is handed the approve call as evm-call with broadcast true, makes that call
from the account itself and answers the hash of the transaction that carried it, so a decline after it keeps what was
sent as moved. The payment is the return the Spend-Permission header carries, as the profile writes it."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Binding, Chosen, Inputs, Json, Refusal, Signature
from ..bindings._lcp import is_list, is_object
from ..bindings.spend_permissions_eip155 import ID, Route, SpendPermissionUnsigned, presented_return
from ._base import BasePiece
from ._common import account_of, broadcasts

_EVM_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")


@dataclass(frozen=True, slots=True)
class Built:
    """The binding's build with the route chosen, which the request is handed by."""

    route: Route
    unsigned: SpendPermissionUnsigned


class SpendPermissionsPiece(BasePiece):
    pairing = ID

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Any) -> Chosen | Refusal:
        """The offer on the account's network, by the route "signature" where it accepts it, else "transaction"."""
        a = account_of(account)
        offer = read.offer
        if a is None or a.namespace != "eip155" or _EVM_ADDRESS.fullmatch(a.address) is None or not is_object(offer):
            return Refusal("spend-permissions/no-payable-option")
        accepts = offer.get("accepts")
        routes = accepts if is_list(accepts) else []
        route = "signature" if "signature" in routes else "transaction" if "transaction" in routes else None
        if offer.get("network") != a.network or route is None:
            return Refusal("spend-permissions/no-payable-option")
        return Chosen(pairing=ID, choice={"offer": dict(offer), "account": a.address, "route": route}, ref=ref)

    def build(self, binding: Binding, choice: Any, h: AtrHash) -> Built | Refusal:
        """The binding's build over the offer and the account, with the route chosen beside it."""
        route = choice.get("route") if is_object(choice) else None
        if route != "signature" and route != "transaction":
            return Refusal("spend-permissions/choice-malformed")
        unsigned = binding.build({"offer": choice.get("offer"), "account": choice.get("account")}, h)
        if isinstance(unsigned, Refusal):
            return unsigned
        if not isinstance(unsigned, SpendPermissionUnsigned):
            return Refusal("spend-permissions/choice-malformed")
        return Built(route, unsigned)

    def request(self, unsigned: Any) -> dict[str, Any] | None | Refusal:
        """The typed data the account signs, or the approve call it makes on the manager's network, exactly as built."""
        if not isinstance(unsigned, Built):
            return Refusal("spend-permissions/choice-malformed")
        typed = unsigned.unsigned.typed_data
        if unsigned.route == "signature":
            return {"kind": "eip712", "typedData": typed}
        approve = unsigned.unsigned.approve
        call = {"to": approve["to"], "data": approve["data"]}
        return {"kind": "evm-call", "chainId": typed["domain"]["chainId"], "call": call, "broadcast": True}

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
        """The return: the offer's network and manager, the whole permission as built, and the signer's answer as the
        signature or as the hash of the transaction that carried the approval; a value the return does not take is
        refused with the code its header gives it."""
        offer = chosen.choice.get("offer") if isinstance(chosen.choice, Mapping) else None
        if not isinstance(unsigned, Built) or not is_object(offer):
            return Refusal("spend-permissions/choice-malformed")
        presented = {
            "network": offer.get("network"),
            "manager": offer.get("manager"),
            "permission": unsigned.unsigned.permission,
            unsigned.route: signature,
        }
        return presented_return(presented)

    def moves(self, request: Json) -> bool:
        """The route "transaction": the signer makes the call from the account before the gate reads what it
        answers."""
        return broadcasts(request)


PIECE = SpendPermissionsPiece()
