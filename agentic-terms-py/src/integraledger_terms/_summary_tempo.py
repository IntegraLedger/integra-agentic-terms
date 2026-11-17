"""tempo-call requests (terms' profile buyer-gate.md, rule 13): one call, call.to with call.data, that the payer's wallet
signs in a Tempo transaction on chain chainId, payable until validBefore. The summary is read only where the call is a
payment channel's open to the escrow call.to and nothing else, the call the protocol package's Tempo session build
writes: the TIP-20 channel reserve's open(address payee, address operator, address token, uint96 deposit, bytes32 salt,
address authorizedSigner) or the earlier escrow's open(address payee, address token, uint128 deposit, bytes32 salt,
address authorizedSigner). Any other call has no summary."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ._types import Payee, Summary, Validity

if TYPE_CHECKING:
    from ._summary import Opened

_ADDRESS_WORD = "0{24}([0-9a-fA-F]{40})"
_WORD = "([0-9a-fA-F]{64})"
# The TIP-20 channel reserve's open: selector 0xedc53b00, then payee, operator, token, deposit, salt, authorizedSigner.
_OPEN_V2 = re.compile(f"0x(?:edc53b00){_ADDRESS_WORD}{_ADDRESS_WORD}{_ADDRESS_WORD}{_WORD}{_WORD}{_ADDRESS_WORD}", re.IGNORECASE)
# The earlier escrow's open: selector 0xc79ea485, then payee, token, deposit, salt, authorizedSigner.
_OPEN_V1 = re.compile(f"0x(?:c79ea485){_ADDRESS_WORD}{_ADDRESS_WORD}{_WORD}{_WORD}{_ADDRESS_WORD}", re.IGNORECASE)
_DECIMAL = re.compile(r"[0-9]{1,78}")
_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
_ZERO = "0x" + "0" * 40


@dataclass(frozen=True, slots=True)
class _Open:
    payee: str
    operator: str | None
    token: str
    deposit: int
    authorized_signer: str


def _decimal(v: object) -> str | None:
    """A non-negative integer as a decimal string: an int (a bool is none) or a decimal string; else None."""
    if isinstance(v, int) and not isinstance(v, bool):
        return str(v) if v >= 0 else None
    return v if isinstance(v, str) and _DECIMAL.fullmatch(v) is not None else None


def _open_of(data: str) -> _Open | None:
    """The open call's members, each address in lower-case hex; None for any other data or a deposit out of range."""
    v2 = _OPEN_V2.fullmatch(data)
    if v2 is not None:
        deposit = int(v2.group(4), 16)
        if deposit >= 1 << 96:
            return None
        operator = "0x" + v2.group(2).lower()
        return _Open(
            payee="0x" + v2.group(1).lower(),
            operator=None if operator == _ZERO else operator,
            token="0x" + v2.group(3).lower(),
            deposit=deposit,
            authorized_signer="0x" + v2.group(6).lower(),
        )
    v1 = _OPEN_V1.fullmatch(data)
    if v1 is None:
        return None
    deposit = int(v1.group(3), 16)
    if deposit >= 1 << 128:
        return None
    return _Open(
        payee="0x" + v1.group(1).lower(),
        operator=None,
        token="0x" + v1.group(2).lower(),
        deposit=deposit,
        authorized_signer="0x" + v1.group(5).lower(),
    )


def tempo_open(request: Mapping[str, Any], network: str | None = None, opened: "Opened | None" = None) -> Summary | None:
    """mpp/session/tempo's opening: the deposit moves from the payer to the escrow call.to, and the channel's payee may
    draw on it with vouchers, which are signed apart, so the summary names no amount. The one payee is the open's payee,
    with the deposit; the asset its token; the network eip155: and chainId; the validity none to validBefore, in
    seconds. deposit is the deposit, operator the TIP-20 channel reserve's operator where it is not the zero address,
    and grant {escrow, authorizedSigner}: the contract that holds the deposit and the key the open names to sign the
    channel's vouchers. Who may close the channel is the escrow's rule, which the call does not state."""
    call = request.get("call")
    # A call of any other member moves what this summary does not read.
    if request.get("kind") != "tempo-call" or not isinstance(call, Mapping) or sorted(call) != ["data", "to"]:
        return None
    chain, before = _decimal(request.get("chainId")), _decimal(request.get("validBefore"))
    escrow, data = call.get("to"), call.get("data")
    if not isinstance(escrow, str) or _ADDRESS.fullmatch(escrow) is None or not isinstance(data, str):
        return None
    found = _open_of(data)
    if chain is None or before is None or before == "0" or found is None:
        return None
    deposit = str(found.deposit)
    return Summary(
        payees=(Payee(account=found.payee, amount=deposit),),
        asset=found.token,
        network=f"eip155:{chain}",
        validity=Validity(not_before=None, not_after=before, unit="seconds"),
        deposit=deposit,
        operator=found.operator,
        grant={"escrow": escrow, "authorizedSigner": found.authorized_signer},
        atr=b"",
    )
