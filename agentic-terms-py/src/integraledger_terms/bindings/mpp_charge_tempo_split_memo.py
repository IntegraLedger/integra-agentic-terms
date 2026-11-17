"""The buyer half of mpp/charge/tempo/split-memo, the pull form, and mpp/charge/tempo/split-memo/push (lcp profile
mpp-charge-tempo-split-memo.md): read, bound and broadcaster. The resource server places one split
{recipient, amount: "1", memo: H} in the challenge's methodDetails.splits, and the stock MPP client (mppx 0.17.6,
pympp 0.20.0) builds one Tempo transaction from the challenge, copying each split's memo into its transferWithMemo call,
so the payer's own signed transaction carries all of H. The protocol package builds nothing for these pairings: the
buyer's stock client builds and signs. On pull the resource server's settler broadcasts the signed transaction the
credential carries; on push the payer broadcasts it and names it by its hash, and bound reads H in the signed bytes the
caller's reader read for that hash, held in Held as @integraledger/lcp holds them under the payment's own FETCHED
member. Nothing here fetches, hashes an ATR or signs."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Act, Advertised, AgreementData, Broadcaster, Coverage, Json, Refusal
from ._codec import hex_bytes
from ._lcp import is_object, normal_hash
from ._mpp import (
    Echoed,
    by_type,
    chain_of,
    credential_of,
    did_pkh_address,
    echoed_for,
    fetched_of,
    mpp_broadcaster,
    read,
    request_address,
    same_bytes,
)
from ._tempo import TRANSFER_WITH_MEMO_SELECTOR, decode_tempo_tx, expiring_nonce_hash, tempo_sender

PULL = "mpp/charge/tempo/split-memo"
PUSH = "mpp/charge/tempo/split-memo/push"

_SELECTOR = bytes.fromhex(TRANSFER_WITH_MEMO_SELECTOR[2:])


def _memo_of(data: bytes) -> bytes | None:
    """The memo of transferWithMemo(address,uint256,bytes32) calldata: exactly 100 bytes, the selector, an address word
    whose 12 leading bytes are zero, the amount and the memo; None for any other input."""
    if len(data) != 100 or data[:4] != _SELECTOR or any(data[4:16]):
        return None
    return data[68:100]


def _signed_split(wire: bytes, chain_id: int, currency: str, h: str) -> str | Refusal:
    """The sender of the signed transaction wire, read for H: at most 65,536 bytes of a 0x76 or 0x78 envelope
    (tempo/tx-too-large, tempo/tx-malformed), signed for chain_id (else tempo/tx-malformed), whose sender Tempo recovers
    from the 0x76 form, a 0x78 envelope naming that sender in item 11; and exactly one transferWithMemo call to currency
    whose memo is h: none is tempo/memo-not-bound, several tempo/ambiguous. Nothing it pays is compared with the
    request."""
    tx = decode_tempo_tx(wire)
    if isinstance(tx, Refusal):
        return tx
    if tx.chain_id != chain_id:
        return Refusal("tempo/tx-malformed")
    sender = tempo_sender(wire)
    if isinstance(sender, Refusal):
        return sender
    memo = bytes.fromhex(h[2:])
    calls = [c for c in tx.calls if c.to is not None and same_bytes(c.to, currency) and _memo_of(c.input) == memo]
    if not calls:
        return Refusal("tempo/memo-not-bound")
    if len(calls) > 1:
        return Refusal("tempo/ambiguous")
    signed = expiring_nonce_hash(wire, sender)
    return signed if isinstance(signed, Refusal) else sender


def _echoed(presented: Any, pairing: str) -> Echoed | Refusal:
    """The echoed challenge held to pairing's filter (echoed_for). On push it may also be one that names pull alone,
    held to the pull form's filter: a payment that already moved under it is the push form's (lcp profile
    mpp-charge-tempo-split-memo.md, rule 3)."""
    e = echoed_for(presented, pairing)
    if pairing == PUSH and isinstance(e, Refusal) and e.code == "mpp/not-this-pairing":
        pull = echoed_for(presented, PULL)
        if not isinstance(pull, Refusal):
            return pull
    return e


def _source_names(credential: Mapping[str, Any], sender: str) -> Refusal | None:
    """A source the credential carries names the sender; one that names another account is tempo/source-not-sender."""
    if "source" not in credential:
        return None
    named = did_pkh_address(credential["source"])
    return None if named is not None and same_bytes(named, sender) else Refusal("tempo/source-not-sender")


def _held(credential: Mapping[str, Any], e: Echoed, currency: str, wire: bytes) -> AtrHash | Refusal:
    """H, once the signed transaction wire carries it under the echoed challenge's chainId and currency and a source
    the credential carries names its sender."""
    h = normal_hash(e.h)
    assert h is not None
    sender = _signed_split(wire, chain_of(e.checked), currency, h)
    if isinstance(sender, Refusal):
        return sender
    named = _source_names(credential, sender)
    return e.h if named is None else named


def _pull_bound(presented: Any) -> AtrHash | Refusal:
    """The pull credential: a payload of type transaction whose signature is the signed transaction, as 0x hex."""
    credential = credential_of(presented)
    if isinstance(credential, Refusal):
        return credential
    e = _echoed(credential, PULL)
    if isinstance(e, Refusal):
        return e
    if e.payload.get("type") != "transaction":
        return Refusal("mpp/credential-type")
    currency = request_address(e.checked, "currency")
    if isinstance(currency, Refusal):
        return currency
    wire = hex_bytes(e.payload.get("signature"))
    if wire is None or len(wire) == 0:
        return Refusal("mpp/credential-malformed")
    return _held(credential, e, currency, wire)


def _push_bound(presented: Any) -> AtrHash | Refusal:
    """The push credential: a payload of type hash naming the transaction, and the read made for it held in Held, its
    transaction that hash, in lower-case hex, and raw its signed bytes; a credential without them is tempo/read-first."""
    credential = credential_of(presented)
    if isinstance(credential, Refusal):
        return credential
    e = _echoed(credential, PUSH)
    if isinstance(e, Refusal):
        return e
    if e.payload.get("type") != "hash":
        return Refusal("mpp/credential-type")
    landed = fetched_of(credential)
    named = normal_hash(e.payload.get("hash"))
    if not is_object(landed) or not isinstance(landed.get("raw"), str) or named is None or landed.get("transaction") != named:
        return Refusal("tempo/read-first")
    currency = request_address(e.checked, "currency")
    if isinstance(currency, Refusal):
        return currency
    wire = hex_bytes(landed["raw"])
    if wire is None:
        return Refusal("tempo/read-first")
    return _held(credential, e, currency, wire)


@dataclass(frozen=True, slots=True)
class MppChargeTempoSplitMemo:
    """mpp/charge/tempo/split-memo: its payment can itself be an agreement, of at least 2 base units, the split carrying
    H and a primary of at least one unit (lcp profile mpp-charge-tempo-split-memo.md, rule 16)."""

    id: str = PULL
    coverage: Coverage = "full"
    agreement: AgreementData | None = AgreementData(floor="2")

    def read(self, doc: Json) -> Advertised | Refusal:
        """H, the link, and the challenges that carry them, in document order."""
        return read(doc)

    def build(self, choice: Json, h: AtrHash, act: Act | None = None) -> Refusal:
        """Nothing: the buyer's stock client builds and signs the transaction."""
        return Refusal("mpp/nothing-to-sign")

    def bound(self, presented: Json, given: Mapping[str, Any] | None = None) -> AtrHash | Refusal:
        """H from the echoed challenge, once the transaction the credential carries holds exactly one transferWithMemo
        call to the request's currency whose memo is H. No signature is verified here but the sender's recovery."""
        return _pull_bound(presented)

    def broadcaster(self, presented: Json) -> Broadcaster | Refusal:
        """"payee" for a credential of type transaction: the resource server's settler broadcasts it. A credential of
        any other type gets mpp/credential-type, as bound refuses it."""
        return mpp_broadcaster(presented, by_type({"transaction": "payee"}))


@dataclass(frozen=True, slots=True)
class MppChargeTempoSplitMemoPush:
    """mpp/charge/tempo/split-memo/push: never an agreement option."""

    id: str = PUSH
    coverage: Coverage = "full"
    agreement: AgreementData | None = None

    def read(self, doc: Json) -> Advertised | Refusal:
        """H, the link, and the challenges that carry them, in document order."""
        return read(doc)

    def build(self, choice: Json, h: AtrHash, act: Act | None = None) -> Refusal:
        """Nothing: the buyer's stock client builds, signs and broadcasts the transaction."""
        return Refusal("mpp/nothing-to-sign")

    def bound(self, presented: Json, given: Mapping[str, Any] | None = None) -> AtrHash | Refusal:
        """H from the echoed challenge, once the landed transaction the credential names holds exactly one
        transferWithMemo call to the request's currency whose memo is H."""
        return _push_bound(presented)

    def broadcaster(self, presented: Json) -> Broadcaster | Refusal:
        """"payer" for a credential of type hash: the payer broadcast the transaction it names. A credential of any
        other type gets mpp/credential-type, as bound refuses it."""
        return mpp_broadcaster(presented, by_type({"hash": "payer"}))
