"""The buyer half of the pairing mpp/session/solana: read, build with complete, bound, and the channel members
(channel_kind, channel_ref, bound_within, build_within).

The ATR hash rides as the channel's salt, H's first 8 bytes read as a little-endian u64, which the payer signs in the
channel program's open instruction; H itself is in the challenge the opening answers. Nothing here fetches, hashes an
ATR or signs.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Json, Refusal
from ._channel import BatchUnsigned, ChannelKind, ChannelRef
from ._codec import b58_decode, canonical_json
from ._lcp import is_object
from ._mpp import Checked, MppUnsigned, chosen_for, credential_of, echoed_for, read
from ._mpp_checks import solana_network_of
from ._session_within import action_kind, echoed_details, within_checks
from ._svm import SvmTx, channel_voucher_message, decode_svm_tx, key_bytes, key_string, static_nonce, wire_of

ID = "mpp/session/solana"
OPEN_DISCRIMINATOR = 1
OPEN_MIN_DATA = 33
OPEN_MIN_ACCOUNTS = 6
OPEN_CHANNEL_ACCOUNT = 5
# The open instruction's authorizedSigner account.
OPEN_SIGNER_ACCOUNT = 4
WITHIN_ACTIONS = ("voucher", "topUp", "use")
U64_LIMIT = 1 << 64


def session_salt(h: AtrHash) -> int:
    """H's first 8 bytes read as a little-endian u64, so the salt's encoded bytes are exactly those 8 bytes."""
    return int.from_bytes(bytes.fromhex(h[2:18]), "little")


def session_proof(channel_id: str, payer: str, challenge_id: str) -> bytes:
    """The UTF-8 of the RFC 8785 JSON of {channelId, domain: "mpp-session-auth-v1", payer, sessionChallengeId}."""
    text = canonical_json(
        {"channelId": channel_id, "domain": "mpp-session-auth-v1", "payer": payer, "sessionChallengeId": challenge_id}
    )
    return text.encode("utf-8")


@dataclass(frozen=True, slots=True)
class Open:
    salt: int
    channel: str


def open_of(tx: SvmTx, program: object) -> Open | Refusal:
    """The one top-level instruction of program whose data starts with the open discriminator, with at least 33 bytes
    of data and 6 accounts: its salt (data bytes 1-8, little-endian) and its channel (account 5)."""
    program_key = key_bytes(program)
    if program_key is None:
        return Refusal("svm/open-not-found")
    opens = [
        ix
        for ix in tx.instructions
        if ix.program < len(tx.keys)
        and tx.keys[ix.program] == program_key
        and len(ix.data) >= OPEN_MIN_DATA
        and ix.data[0] == OPEN_DISCRIMINATOR
        and len(ix.accounts) >= OPEN_MIN_ACCOUNTS
    ]
    if len(opens) != 1:
        return Refusal("svm/open-not-found")
    ix = opens[0]
    position = ix.accounts[OPEN_CHANNEL_ACCOUNT]
    if position >= len(tx.keys):
        return Refusal("svm/open-not-found")
    return Open(int.from_bytes(ix.data[1:9], "little"), key_string(tx.keys[position]))


@dataclass(frozen=True, slots=True)
class Opening:
    """A checked opening: its H, its echoed challenge checked, its payload and its signed transaction."""

    h: AtrHash
    checked: Checked
    payload: Mapping[str, Any]
    tx: SvmTx


def _opening(presented: Mapping[str, Any]) -> Opening | Refusal:
    """The opening's checks: the one open of the challenge's program, its salt H's first 8 bytes, its channel the
    payload's, and any authentication naming the challenge."""
    e = echoed_for(presented, ID)
    if isinstance(e, Refusal):
        return e
    if e.payload.get("action") != "open":
        return Refusal("mpp/session-action")
    wire = wire_of(e.payload.get("transaction"))
    if isinstance(wire, Refusal):
        return wire
    tx = decode_svm_tx(wire)
    if isinstance(tx, Refusal):
        return tx
    from_table = static_nonce(tx)
    if from_table is not None:
        return from_table
    opened = open_of(tx, e.checked.details.get("channelProgram"))
    if isinstance(opened, Refusal):
        return opened
    if opened.salt != session_salt(e.h):
        return Refusal("mpp/carrier-not-challenge")
    declared = key_bytes(e.payload.get("channelId"))
    if declared is None or key_string(declared) != opened.channel:
        return Refusal("svm/channel-mismatch")
    if "authentication" in e.payload:
        auth = e.payload["authentication"]
        if not is_object(auth) or auth.get("challengeId") != presented["challenge"].get("id"):
            return Refusal("svm/proof-not-challenge")
    return Opening(e.h, e.checked, e.payload, tx)


def open_signer(tx: SvmTx, program: object) -> str | Refusal:
    """The authorizedSigner account of the first top-level instruction of program whose data starts with the open
    discriminator."""
    program_key = key_bytes(program)
    ix = next(
        (
            i
            for i in tx.instructions
            if program_key is not None
            and i.program < len(tx.keys)
            and tx.keys[i.program] == program_key
            and len(i.data) > 0
            and i.data[0] == OPEN_DISCRIMINATOR
        ),
        None,
    )
    if ix is None or len(ix.accounts) <= OPEN_SIGNER_ACCOUNT or ix.accounts[OPEN_SIGNER_ACCOUNT] >= len(tx.keys):
        return Refusal("svm/open-not-found")
    return key_string(tx.keys[ix.accounts[OPEN_SIGNER_ACCOUNT]])


def is_base58_signature(value: object) -> bool:
    """A base58 string of 64 to 88 characters that decodes to a 64-byte Ed25519 signature."""
    if not isinstance(value, str) or not 64 <= len(value) <= 88:
        return False
    decoded = b58_decode(value)
    return decoded is not None and len(decoded) == 64


@dataclass(frozen=True, slots=True)
class MppSessionSolana:
    id: str = ID
    public_proof: bool = True

    def read(self, doc: Json) -> Advertised | Refusal:
        """H, the link, and the challenges that carry them, in document order."""
        return read(doc)

    def build(self, choice: Json, h: AtrHash) -> MppUnsigned | Refusal:
        """The values the buyer's channel client composes the open from: the salt (H's first 8 bytes), the program,
        the network and the request's blockhash and slot. complete checks the composed open before returning the
        credential."""
        if not is_object(choice):
            return Refusal("svm/input-malformed")
        checked = chosen_for(choice.get("challenge"), h, ID)
        if isinstance(checked, Refusal):
            return checked
        network = solana_network_of(checked.details, True)
        if network is None:
            return Refusal("svm/network-undeclared")
        if isinstance(network, Refusal):
            return network
        challenge = choice["challenge"]
        d = checked.details

        def complete(open_payload: Any) -> dict[str, Any] | Refusal:
            if not is_object(open_payload) or open_payload.get("action") != "open":
                return Refusal("mpp/session-action")
            credential = {"challenge": challenge, "payload": open_payload}
            o = _opening(credential)
            return o if isinstance(o, Refusal) else credential

        request = {
            "kind": "solana-session-open",
            "salt": session_salt(h),
            "channelProgram": d["channelProgram"],
            "network": network,
            "recentBlockhash": d["recentBlockhash"],
            "recentSlot": int(d["recentSlot"]),
        }
        return MppUnsigned(request, complete)

    def bound(self, presented: Json) -> AtrHash | Refusal:
        """H from the echoed challenge, once the signed open's salt is H's first 8 bytes and its channel the
        payload's. No signature is verified here."""
        credential = credential_of(presented)
        if isinstance(credential, Refusal):
            return credential
        o = _opening(credential)
        return o if isinstance(o, Refusal) else o.h

    def channel_kind(self, presented: Json) -> ChannelKind | Refusal:
        """open, close, or within for a voucher, topUp or use."""
        return action_kind(presented, WITHIN_ACTIONS)

    def channel_ref(self, presented: Json) -> ChannelRef | Refusal:
        """The network and the payload's channelId, re-encoded from its 32 bytes; on a within or close payment, read
        from the payment itself."""
        kind = action_kind(presented, WITHIN_ACTIONS)
        if isinstance(kind, Refusal):
            return kind
        details: Mapping[str, Any]
        if kind == "open":
            e = echoed_for(presented, ID)
            if isinstance(e, Refusal):
                return e
            details = e.checked.details
        else:
            d = echoed_details(presented, "solana")
            if isinstance(d, Refusal):
                return d
            details = d
        network = solana_network_of(details, True)
        if network is None:
            return Refusal("svm/network-undeclared")
        if isinstance(network, Refusal):
            return network
        assert is_object(presented)
        channel = key_bytes(presented["payload"].get("channelId"))
        return Refusal("mpp/credential-malformed") if channel is None else ChannelRef(network, key_string(channel))

    def bound_within(self, presented: Json) -> AtrHash | Refusal:
        """A use credential echoing the opening challenge, whose bearer proof names that challenge's id, gives its H.
        A voucher or topUp signs no value holding H."""
        credential = credential_of(presented)
        if isinstance(credential, Refusal):
            return credential
        kind = action_kind(credential, WITHIN_ACTIONS)
        if isinstance(kind, Refusal):
            return kind
        if credential["payload"].get("action") != "use":
            return Refusal("mpp/not-bound-within")
        e = echoed_for(credential, ID)
        if isinstance(e, Refusal):
            return e
        auth = e.payload.get("authentication")
        if not is_object(auth) or auth.get("challengeId") != credential["challenge"].get("id"):
            return Refusal("svm/proof-not-challenge")
        return e.h

    def build_within(self, w: Mapping[str, Any], h: AtrHash) -> BatchUnsigned | Refusal:
        """A voucher, or a close's voucher, on the channel the held opening opened, for its client voucher signer: one
        ed25519-raw request over the channel voucher message (channel id, cumulative amount, no expiry), for the
        signer the opening's open instruction named. An operator channel's vouchers are the operator's, and are not
        built."""
        o = within_checks(w, h, "session/solana", _opening, U64_LIMIT)
        if isinstance(o, Refusal):
            return o
        if o.checked.details.get("voucherSigner") == "operator":
            return Refusal("mpp/within-action-not-built")
        signer = open_signer(o.tx, o.checked.details.get("channelProgram"))
        if isinstance(signer, Refusal):
            return signer
        channel = key_bytes(w["opening"]["payload"].get("channelId"))
        if channel is None:
            return Refusal("mpp/credential-malformed")
        channel_id = key_string(channel)
        message = channel_voucher_message(channel_id, w["cumulativeAmount"], 0)
        if message is None:
            return Refusal("svm/input-malformed")
        challenge = dict(w["challenge"])
        action = w["action"]
        amount = str(w["cumulativeAmount"])

        def complete(signatures: Any) -> dict[str, Any] | Refusal:
            signature = signatures[0] if isinstance(signatures, (list, tuple)) and len(signatures) == 1 else None
            if not is_base58_signature(signature):
                return Refusal("mpp/credential-malformed")
            voucher = {"voucher": {"channelId": channel_id, "cumulativeAmount": amount}, "signer": signer, "signature": signature, "signatureType": "ed25519"}
            return {"challenge": challenge, "payload": {"action": action, "channelId": channel_id, "voucher": voucher}}

        return BatchUnsigned(requests=[{"kind": "ed25519-raw", "message": message, "signer": signer}], complete=complete)


MPP_SESSION_SOLANA = MppSessionSolana()
