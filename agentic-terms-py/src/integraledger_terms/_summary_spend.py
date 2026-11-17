"""The approval summary of spend-permissions/eip155's requests (terms' profile buyer-gate.md, rule 13): the account
approves a Spend Permission, which lets its spender draw token from the account, up to allowance in each period, from
start until end (lcp profile spend-permissions-eip155.md). On the route "signature" the account signs the permission as
EIP-712 typed data in the SpendPermissionManager's domain (eip712); on the route "transaction" it calls the manager's
approve(SpendPermission) with it (evm-call). The summary is read from the permission either request carries, in the
form the binding's build writes; any other request answers None, so the gate declines it summary-missing."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ._types import Payee, Summary, Validity
from .bindings._lcp import is_address
from .bindings.spend_permissions_eip155 import APPROVE_SELECTOR, DOMAIN_NAME, DOMAIN_VERSION, SPEND_PERMISSION_FIELDS

if TYPE_CHECKING:
    # The registry in _summary imports this module's function; the type is only named here.
    from ._summary import Opened

_DECIMAL = re.compile(r"[0-9]{1,78}")
_HEX = re.compile(r"[0-9a-fA-F]*")


def _decimal(v: object) -> str | None:
    """A non-negative integer as a decimal string: an int (a bool is none) or a decimal string; else None."""
    if isinstance(v, int) and not isinstance(v, bool):
        return str(v) if v >= 0 else None
    return v if isinstance(v, str) and _DECIMAL.fullmatch(v) is not None else None


@dataclass(frozen=True, slots=True)
class _Granted:
    """What the summary shows of a permission, each integer a decimal string, and the chain it is approved on."""

    spender: str
    token: str
    allowance: str
    period: str
    start: str
    end: str
    chain: str


def _type_is(members: object) -> bool:
    """Whether the typed data's SpendPermission members are exactly the manager's, in its order."""
    if not isinstance(members, list) or len(members) != len(SPEND_PERMISSION_FIELDS):
        return False
    return all(
        isinstance(m, Mapping) and len(m) == 2 and m.get("name") == name and m.get("type") == type_
        for m, (name, type_) in zip(members, SPEND_PERMISSION_FIELDS)
    )


def _signed(request: Mapping[str, Any]) -> _Granted | None:
    """The typed data's permission, under exactly the manager's type and domain; None for any other request."""
    typed = request.get("typedData")
    if request.get("kind") != "eip712" or not isinstance(typed, Mapping) or typed.get("primaryType") != "SpendPermission":
        return None
    types, m, d = typed.get("types"), typed.get("message"), typed.get("domain")
    if not isinstance(types, Mapping) or not isinstance(m, Mapping) or not isinstance(d, Mapping):
        return None
    if not _type_is(types.get("SpendPermission")) or d.get("name") != DOMAIN_NAME or d.get("version") != DOMAIN_VERSION:
        return None
    spender, token = m.get("spender"), m.get("token")
    if not is_address(d.get("verifyingContract")) or not is_address(spender) or not is_address(token):
        return None
    allowance, period, start, end, chain = (
        _decimal(x) for x in (m.get("allowance"), m.get("period"), m.get("start"), m.get("end"), d.get("chainId"))
    )
    if allowance is None or period is None or start is None or end is None or chain is None:
        return None
    return _Granted(spender, token, allowance, period, start, end, chain)


def _fits(w: str, zeros: int) -> bool:
    """Whether the first zeros bytes of hex digits are zero."""
    return set(w[: 2 * zeros]) <= {"0"}


def _approved(request: Mapping[str, Any]) -> _Granted | None:
    """The permission an approve(SpendPermission) call carries, in the ABI's one form the binding writes: the selector,
    the tuple's offset (32), its nine head words, each within its type's width, extraData's offset from the tuple (288),
    its length and its bytes padded with zeros to a word, and nothing after; None for any other call."""
    call = request.get("call")
    if request.get("kind") != "evm-call" or not isinstance(call, Mapping) or set(call.keys()) != {"data", "to"}:
        return None
    chain, data = _decimal(request.get("chainId")), call.get("data")
    if chain is None or not is_address(call.get("to")) or not isinstance(data, str):
        return None
    if not data.lower().startswith(APPROVE_SELECTOR) or _HEX.fullmatch(data[10:]) is None:
        return None
    body = data[10:]
    if len(body) % 64 != 0 or len(body) < 64 * 11:
        return None

    def w(i: int) -> str:
        return body[64 * i : 64 * i + 64]

    n = int(w(10), 16)
    if int(w(0), 16) != 32 or int(w(9), 16) != 288 or n > len(body) // 2:
        return None
    padded = -(-n // 32) * 32
    if len(body) != 64 * 11 + 2 * padded or not _fits(body[64 * 11 + 2 * n :], padded - n):
        return None
    if not all(_fits(w(i), 12) for i in (1, 2, 3, 4)) or not all(_fits(w(i), 26) for i in (5, 6, 7)):
        return None
    return _Granted(
        spender="0x" + w(2)[24:],
        token="0x" + w(3)[24:],
        allowance=str(int(w(4), 16)),
        period=str(int(w(5), 16)),
        start=str(int(w(6), 16)),
        end=str(int(w(7), 16)),
        chain=chain,
    )


def spend_permission(request: Mapping[str, Any], network: str | None = None, opened: "Opened | None" = None) -> Summary | None:
    """spend-permissions/eip155: the one payee is the spender, with the allowance as its part; the period is period,
    the limit per period allowance and the end end; the asset is token, the network eip155: and the chain id; and the
    validity start to end, in seconds, while the spender may draw. The approval itself moves nothing, so the summary
    shows no amount."""
    p = _signed(request) or _approved(request)
    if p is None:
        return None
    return Summary(
        payees=(Payee(account=p.spender, amount=p.allowance),),
        period=p.period,
        limit_per_period=p.allowance,
        end=p.end,
        asset=p.token,
        network=f"eip155:{p.chain}",
        validity=Validity(not_before=p.start, not_after=p.end, unit="seconds"),
        atr=b"",
    )
