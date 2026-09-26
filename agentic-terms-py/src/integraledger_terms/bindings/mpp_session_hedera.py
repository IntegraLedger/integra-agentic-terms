"""The buyer half of mpp/session/hedera: read, build with complete, bound, and the channel members. The payer's signer
broadcasts approve and then the escrow's open with H as the channel's salt, and signs the zero voucher on the resulting
channel; bound reads the escrow's ChannelOpened log from the opening's landed receipt. A later voucher, or the close's
final voucher, is built from the held opening. Nothing here fetches or signs."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash, hash_equals
from .._keccak import keccak256
from .._types import Advertised, Json, Refusal
from ._channel import BatchUnsigned, ChannelKind, ChannelRef
from ._evm import ZERO_ADDRESS, address_of_word, address_word, bytes32_word, bytes_of, hex_of, uint_word
from ._lcp import is_address, is_list, is_object, normal_hash
from ._mpp import Echoed, chosen_for, credential_of, echoed_for, read
from ._mpp_checks import hedera_session_network_of
from ._session_within import action_kind, echoed_details, within_checks

ID = "mpp/session/hedera"
ESCROW_OPEN_SELECTOR = bytes.fromhex("c79ea485")
APPROVE_SELECTOR = bytes.fromhex("095ea7b3")
CHANNEL_OPENED_TOPIC = "0xcd6e60364f8ee4c2b0d62afc07a1fb04fd267ce94693f93f8f85daaa099b5c94"
U128_LIMIT = 1 << 128
APPROVE_GAS = 1_000_000
OPEN_GAS = 1_500_000


def channel_id(payer: str, payee: str, token: str, salt: str, signer: str, escrow: str, chain_id: int) -> str:
    """keccak256(abi.encode(payer, payee, token, salt, authorizedSigner, escrow, chainId)), lower-case."""
    words = (
        address_word(payer)
        + address_word(payee)
        + address_word(token)
        + bytes32_word(salt)
        + address_word(signer)
        + address_word(escrow)
        + uint_word(chain_id)
    )
    return hex_of(keccak256(words))


def voucher(channel: str, escrow: str, chain_id: int, cumulative: int) -> dict[str, Any]:
    """The EIP-712 voucher Voucher(bytes32 channelId, uint128 cumulativeAmount) under the escrow's domain."""
    return {
        "domain": {"name": "Hedera Stream Channel", "version": "1", "chainId": chain_id, "verifyingContract": escrow.lower()},
        "primaryType": "Voucher",
        "types": {"Voucher": [{"name": "channelId", "type": "bytes32"}, {"name": "cumulativeAmount", "type": "uint128"}]},
        "message": {"channelId": channel.lower(), "cumulativeAmount": cumulative},
    }


WITHIN_ACTIONS = ("voucher", "topUp", "use")


def _opening(presented: Mapping[str, Any]) -> Echoed | Refusal:
    """The echoed opening challenge of an open payload."""
    e = echoed_for(presented, ID)
    if isinstance(e, Refusal):
        return e
    if e.payload.get("action") != "open":
        return Refusal("mpp/session-action")
    return e


def _chain(network: str) -> int:
    return 295 if network == "hedera:mainnet" else 296


def _is_log(log: object) -> bool:
    if not is_object(log):
        return False
    topics = log.get("topics")
    return (
        isinstance(log.get("address"), str)
        and is_list(topics)
        and all(isinstance(t, str) for t in topics)
        and isinstance(log.get("data"), str)
    )


@dataclass(frozen=True, slots=True)
class SessionUnsigned:
    """The two calls the payer's signer broadcasts in order, the zero voucher it signs, and how its answer completes
    the opening credential."""

    request: dict[str, Any]
    _challenge: Mapping[str, Any]
    _channel: str

    def complete(self, signed: object) -> dict[str, Any] | Refusal:
        """Takes {openTx: the opening's 32-byte hash, signature: the voucher signature as 0x hex}."""
        if not is_object(signed) or normal_hash(signed.get("openTx")) is None:
            return Refusal("mpp/credential-malformed")
        signature = signed.get("signature")
        if not isinstance(signature, str) or bytes_of(signature) is None:
            return Refusal("mpp/credential-malformed")
        payload = {
            "action": "open",
            "channelId": self._channel,
            "txHash": signed["openTx"],
            "cumulativeAmount": "0",
            "signature": signature,
        }
        return {"challenge": self._challenge, "payload": payload}


@dataclass(frozen=True, slots=True)
class MppSessionHedera:
    id: str = ID
    public_proof: bool = True

    def read(self, doc: Json) -> Advertised | Refusal:
        """H, the link, the agreement URL when named, and the challenges that carry them, in document order."""
        return read(doc)

    def build(self, choice: Json, h: AtrHash) -> SessionUnsigned | Refusal:
        """approve(escrow, deposit) on the currency, then the escrow's open(recipient, currency, deposit, H, zero
        signer), and the zero voucher on the channel that opening creates."""
        if not is_object(choice):
            return Refusal("mpp/input-malformed")
        challenge = choice.get("challenge")
        checked = chosen_for(challenge, h, ID)
        if isinstance(checked, Refusal):
            return checked
        payer, deposit = choice.get("from"), choice.get("deposit")
        if not is_address(payer) or not isinstance(deposit, int) or isinstance(deposit, bool) or not 0 < deposit < U128_LIMIT:
            return Refusal("mpp/input-malformed")
        network = hedera_session_network_of(checked.details)
        if isinstance(network, Refusal):
            return network
        assert is_object(challenge) and isinstance(h, str)
        chain_id = _chain(network)
        escrow = str(checked.details["escrowContract"]).lower()
        currency = str(checked.request["currency"]).lower()
        recipient = str(checked.request["recipient"]).lower()
        channel = channel_id(payer.lower(), recipient, currency, h, ZERO_ADDRESS, escrow, chain_id)
        approve = APPROVE_SELECTOR + address_word(escrow) + uint_word(deposit)
        open_ = ESCROW_OPEN_SELECTOR + address_word(recipient) + address_word(currency) + uint_word(deposit)
        open_ += bytes32_word(h) + address_word(ZERO_ADDRESS)
        request = {
            "kind": "hedera-session-open",
            "chainId": chain_id,
            "calls": [
                {"to": currency, "data": hex_of(approve), "gas": APPROVE_GAS},
                {"to": escrow, "data": hex_of(open_), "gas": OPEN_GAS},
            ],
            "voucher": voucher(channel, escrow, chain_id, 0),
        }
        return SessionUnsigned(request=request, _challenge=challenge, _channel=channel)

    def bound(self, presented: Json) -> AtrHash | Refusal:
        """H from the echoed challenge, once exactly one landed ChannelOpened from the escrow names payload.channelId,
        its salt is H, and the channel id recomputed from the event (payer, payee, token, signer, salt, escrow, chain)
        is that id."""
        credential = credential_of(presented)
        if isinstance(credential, Refusal):
            return credential
        e = echoed_for(credential, ID)
        if isinstance(e, Refusal):
            return e
        if e.payload.get("action") != "open":
            return Refusal("mpp/session-action")
        landed = credential.get("landed")
        logs = landed.get("logs") if is_object(landed) else None
        if not is_list(logs):
            return Refusal("hedera/read-first")
        channel = normal_hash(e.payload.get("channelId"))
        if channel is None:
            return Refusal("mpp/credential-malformed")
        escrow = str(e.checked.details["escrowContract"]).lower()
        opened = [
            log
            for log in logs
            if _is_log(log)
            and log["address"].lower() == escrow
            and len(log["topics"]) == 4
            and log["topics"][0].lower() == CHANNEL_OPENED_TOPIC
            and log["topics"][1].lower() == channel
            and (data := bytes_of(log["data"])) is not None
            and len(data) == 128
        ]
        if len(opened) != 1:
            return Refusal("hedera/channel-log-not-found")
        log = opened[0]
        data = bytes_of(log["data"])
        assert data is not None
        salt = hex_of(data[64:96])
        if not hash_equals(salt, e.h):
            return Refusal("mpp/carrier-not-challenge")
        network = hedera_session_network_of(e.checked.details)
        if isinstance(network, Refusal):
            return network
        payer_word, payee_word = bytes_of(log["topics"][2]), bytes_of(log["topics"][3])
        payer = address_of_word(payer_word) if payer_word is not None else None
        payee = address_of_word(payee_word) if payee_word is not None else None
        token = address_of_word(data[0:32])
        signer = address_of_word(data[32:64])
        if payer is None or payee is None or token is None or signer is None:
            return Refusal("hedera/channel-log-not-found")
        if channel_id(payer, payee, token, salt, signer, escrow, _chain(network)) != channel:
            return Refusal("hedera/channel-id-mismatch")
        return e.h

    def channel_kind(self, presented: Json) -> ChannelKind | Refusal:
        """open, close, or within for a voucher, topUp or use."""
        return action_kind(presented, WITHIN_ACTIONS)

    def channel_ref(self, presented: Json) -> ChannelRef | Refusal:
        """The network and the payload's channelId, lower-case; on a within or close payment, read from the payment
        itself."""
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
            d = echoed_details(presented, "hedera")
            if isinstance(d, Refusal):
                return d
            details = d
        network = hedera_session_network_of(details)
        if isinstance(network, Refusal):
            return network
        assert is_object(presented)
        channel = normal_hash(presented["payload"].get("channelId"))
        return Refusal("mpp/credential-malformed") if channel is None else ChannelRef(network, channel)

    def bound_within(self, presented: Json) -> AtrHash | Refusal:
        """A voucher names only the channel: it signs no value holding H."""
        return Refusal("mpp/not-bound-within")

    def build_within(self, w: Mapping[str, Any], h: AtrHash) -> BatchUnsigned | Refusal:
        """A voucher, or a close's final voucher, on the channel the held opening opened: the voucher with the channel
        id, the escrow and the chain from the opening, signed as EIP-712."""
        o = within_checks(w, h, "session/hedera", _opening, U128_LIMIT)
        if isinstance(o, Refusal):
            return o
        network = hedera_session_network_of(o.checked.details)
        if isinstance(network, Refusal):
            return network
        channel = normal_hash(o.payload.get("channelId"))
        if channel is None:
            return Refusal("mpp/credential-malformed")
        escrow = str(o.checked.details["escrowContract"]).lower()
        typed = voucher(channel, escrow, _chain(network), w["cumulativeAmount"])
        challenge = dict(w["challenge"])
        action = w["action"]
        amount = str(w["cumulativeAmount"])

        def complete(signatures: Any) -> dict[str, Any] | Refusal:
            signature = signatures[0] if isinstance(signatures, (list, tuple)) and len(signatures) == 1 else None
            data = bytes_of(signature) if isinstance(signature, str) else None
            if data is None or len(data) < 65:
                return Refusal("mpp/credential-malformed")
            return {"challenge": challenge, "payload": {"action": action, "channelId": channel, "cumulativeAmount": amount, "signature": signature}}

        return BatchUnsigned(requests=[{"kind": "eip712", "typedData": typed}], complete=complete)
