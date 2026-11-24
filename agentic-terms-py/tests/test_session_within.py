"""The in-channel payment of MPP's sessions: build_within of each session binding, so the Python gate's within
serves MPP sessions as the TypeScript gate's does; and the within challenge the seller issues itself on a live
channel, with its own id and the channel named in methodDetails.channelId: the gate signs only for a channel it opened
for an ATR it compared, and only when the within challenge's legal context is absent or names that H. The voucher
digests and bytes are the vector files' (ES5, TS4, XS3 on XS2's opening); the within challenges are
the issued request with methodDetails.channelId added, a fresh id, and no opaque unless a legal context is given. The
TypeScript gate's tests are channels.test.ts's."""

import asyncio
import base64
import functools
import json
from typing import Any

import pytest

from integraledger_terms import (
    MPP_SESSION_EVM,
    MPP_SESSION_TEMPO,
    MPP_SESSION_XRPL,
    Declined,
    Finished,
    Within,
    _gate,
    open_channel,
    within,
)
from integraledger_terms._types import Refusal
from integraledger_terms.bindings._channel import BatchUnsigned
from integraledger_terms.bindings._mpp import pairings_of
from integraledger_terms.bindings._svm import PAYMENT_CHANNELS, key_bytes
from integraledger_terms.bindings.mpp_session import MppSessionEvm, MppSessionTempo
from integraledger_terms.bindings.mpp_session_xrpl import MppSessionXrpl

from breadth import H, LINK, Recording, offered
from mpp_docs import b64u, issued, placed_doc
from support import STAND_IN, digest, load, piece_transact, recover, sign_typed

EVM = load("mpp-session-evm.json")
TEMPO = load("mpp-session-tempo.json")
HS = load("mpp-session-hedera-solana-xrpl.json")
MC = load("mpp-challenge.json")["fixed"]
TF = TEMPO["fixed"]
H_OTHER = "0x" + "11" * 32


@pytest.fixture(autouse=True)
def frozen_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: TF["now"])


def b6(v: dict[str, Any]) -> dict[str, Any]:
    presented = next(r for r in v["buyer"]["rows"] if r["name"] == "B6")["input"]["presented"]
    assert isinstance(presented, dict), presented
    return presented


def build(binding: Any, opening: dict[str, Any], amount: int, action: str = "voucher") -> BatchUnsigned:
    w = {"challenge": opening["challenge"], "opening": opening, "cumulativeAmount": amount, "action": action}
    unsigned = binding.build_within(w, H)
    assert isinstance(unsigned, BatchUnsigned), unsigned
    return unsigned


# ── build_within against the vectors' voucher digests.


def test_evm_build_within_at_zero_is_es5s_voucher() -> None:
    unsigned = build(MPP_SESSION_EVM, b6(EVM), 0)
    assert [r["kind"] for r in unsigned.requests] == ["eip712"]
    assert digest(unsigned.requests[0]["typedData"]) == EVM["ES5"]["expectVoucherDigest"]


def tempo_opened() -> Finished:
    """A tempo session opened by the pairing's own steps over abc, with no gate."""
    doc = placed_doc(issued("tempo", "session", TF["requestV2"]), H, LINK)
    from test_mpp_session import TempoAnswer

    out = asyncio.run(piece_transact(doc, MPP_SESSION_TEMPO, Recording(f"eip155:42431:{TF['payer']}", TempoAnswer()), {"deposit": TF["deposit"]}))
    assert isinstance(out, Finished) and out.signed is not None, out
    return out


def test_tempo_v2_build_within_at_0_and_250_are_ts4s_vouchers() -> None:
    opening = tempo_opened().signed
    assert opening is not None
    zero = build(MPP_SESSION_TEMPO, opening, 0)
    assert digest(zero.requests[0]["typedData"]) == TEMPO["TS4"]["expectVoucher0"]
    at250 = digest(build(MPP_SESSION_TEMPO, opening, 250).requests[0]["typedData"])
    e = TEMPO["TS4"]["expectVoucher250"]
    assert at250.startswith(e["prefix"]) and at250.endswith(e["suffix"])
    credential = zero.complete([sign_typed(zero.requests[0]["typedData"])])
    assert isinstance(credential, dict)
    assert credential["payload"]["descriptor"] == opening["payload"]["descriptor"]


# mppx's client writes source, the payer's DID, on every session credential (0.17.6 and 0.21.1,
# tempo/session/client/ChannelOps.js serializeCredential); its server reads the payer from it, refuses a voucher or close
# without it ("credential source does not match channel"), and 0.21.1 one naming the authorized signer.
def test_tempo_every_voucher_and_close_carries_source_the_payers_did() -> None:
    opening = tempo_opened().signed
    assert opening is not None
    for action in ("voucher", "close"):
        unsigned = build(MPP_SESSION_TEMPO, opening, 250, action)
        credential = unsigned.complete([sign_typed(r["typedData"]) for r in unsigned.requests])
        assert isinstance(credential, dict), credential
        assert credential["source"] == f"did:pkh:eip155:42431:{TF['payer'].lower()}"
        assert list(credential) == ["challenge", "source", "payload"]


# mppx 0.17.6 and 0.21.1: the v2 close credential's schema requires closeSignature (tempo/Methods.js), and
# verifyCloseAuthorization holds it to the payer or the authorized signer over CloseAuthorization(bytes32 channelId,uint96
# cumulativeAmount) under the voucher's domain.
def test_tempo_v2_close_is_the_final_voucher_then_the_close_authorization() -> None:
    opening = tempo_opened().signed
    assert opening is not None
    unsigned = build(MPP_SESSION_TEMPO, opening, 250, "close")
    assert [r["kind"] for r in unsigned.requests] == ["eip712", "eip712"]
    voucher, close = (r["typedData"] for r in unsigned.requests)
    assert digest(voucher).startswith(TEMPO["TS4"]["expectVoucher250"]["prefix"])
    assert close == {
        "domain": {"name": "TIP20 Channel Reserve", "version": "1", "chainId": 42431, "verifyingContract": TF["escrowV2"]},
        "primaryType": "CloseAuthorization",
        "types": {"CloseAuthorization": [{"name": "channelId", "type": "bytes32"}, {"name": "cumulativeAmount", "type": "uint96"}]},
        "message": {"channelId": TEMPO["TS3"]["expectChannelId"], "cumulativeAmount": 250},
    }
    signature, close_signature = sign_typed(voucher), sign_typed(close)
    # The close authorization is another typed data than the voucher: its signature differs, and recovers the payer.
    assert close_signature != signature
    assert recover(close, close_signature).lower() == TF["payer"].lower()
    assert recover(close, signature).lower() != TF["payer"].lower()
    credential = unsigned.complete([signature, close_signature])
    assert isinstance(credential, dict), credential
    assert credential["payload"] == {
        "action": "close",
        "channelId": TEMPO["TS3"]["expectChannelId"],
        "cumulativeAmount": "250",
        "signature": signature,
        "closeSignature": close_signature,
        "descriptor": opening["payload"]["descriptor"],
    }
    channel = MPP_SESSION_TEMPO.channel  # type: ignore[attr-defined]
    assert channel.kind(credential) == "close"
    assert channel.bound_within(credential) == H
    for sigs in ([signature], [signature, close_signature, signature], [signature, "0x"], ["0x", close_signature], [signature, "close"]):
        assert unsigned.complete(sigs) == Refusal("mpp/credential-malformed"), sigs
    assert len(build(MPP_SESSION_TEMPO, opening, 250).requests) == 1


XRPL_OPENING = {
    "challenge": HS["SS1"]["xrpl"]["placed"],
    "payload": {"action": "open", "transaction": HS["XS2"]["blob"], "amount": "100", "signature": "00"},
}
def agreed(prefix: str) -> str:
    """The code of the one agreedRefusals row of the session file whose case starts with prefix."""
    codes = [r["expect"] for r in HS["agreedRefusals"]["rows"] if r["case"].startswith(prefix)]
    assert len(codes) == 1, (prefix, codes)
    found: str = codes[0]
    return found


def test_xrpl_build_within_at_100_is_xs3s_claim_on_xs2s_channel() -> None:
    # The credential names the channel's payer, XS2's account, the opening's Account, by source, as the opening's
    # credential does, on the within challenge's network, testnet (xrpl:1), as @integraledger/lcp 0.6.3's buildWithin
    # writes it; the stock xrpl-mpp-sdk 0.1.0-beta.4 channel server refuses a voucher or a close without it ("credential
    # source is required").
    unsigned = build(MPP_SESSION_XRPL, XRPL_OPENING, int(HS["XS3"]["drops"]))
    channel = HS["XS2"]["expectChannel"]
    source = f"did:pkh:xrpl:1:{HS['XS2']['account']}"
    assert unsigned.requests == [
        {"kind": "xrpl-claim", "channelId": channel, "drops": int(HS["XS3"]["drops"]), "bytes": bytes.fromhex(HS["XS3"]["expect"])}
    ]
    assert unsigned.complete(["C0" * 64]) == {
        "challenge": XRPL_OPENING["challenge"],
        "source": source,
        "payload": {"action": "voucher", "channelId": channel, "amount": HS["XS3"]["drops"], "signature": "C0" * 64},
    }
    closed = build(MPP_SESSION_XRPL, XRPL_OPENING, 200, "close")
    assert closed.complete(["C0" * 64]) == {
        "challenge": XRPL_OPENING["challenge"],
        "source": source,
        "payload": {"action": "close", "channelId": channel, "amount": "200", "signature": "C0" * 64},
    }
    assert unsigned.complete(["0x" + "C0" * 64]) == Refusal("mpp/credential-malformed")


def test_xrpl_build_within_refuses_an_action_the_draft_does_not_define_as_channel_kind_does() -> None:
    # draft-xrpl-session-00 L334-377 at tempoxyz/mpp-specs 08e7dd87, as the session file's row cites it: the payload's
    # action is open, voucher or close. Any other, a topUp among them, is mpp/session-action from build_within as from
    # channel_kind.
    xrpl = MPP_SESSION_XRPL
    assert isinstance(xrpl, MppSessionXrpl)
    code = agreed("an xrpl topUp, use or bearer")
    for action in ("topUp", "use", "bearer"):
        presented = {"challenge": XRPL_OPENING["challenge"], "payload": {"action": action, "channelId": HS["XS2"]["expectChannel"]}}
        assert xrpl.channel_kind(presented) == Refusal(code)
        w = {"challenge": XRPL_OPENING["challenge"], "opening": XRPL_OPENING, "cumulativeAmount": 100, "action": action}
        assert xrpl.build_within(w, H) == Refusal(code)


def test_build_within_refuses_an_action_it_does_not_build_and_another_hash() -> None:
    evm = MPP_SESSION_EVM
    assert isinstance(evm, MppSessionEvm)
    opening = b6(EVM)
    w = {"challenge": opening["challenge"], "opening": opening, "cumulativeAmount": 1, "action": "topUp"}
    assert evm.build_within(w, H) == Refusal("mpp/within-action-not-built")
    assert evm.build_within({**w, "action": "voucher"}, H_OTHER) == Refusal("mpp/id-not-ours")


def test_build_within_checks_h_the_amount_and_the_action_before_the_opening() -> None:
    """build_within checks H's form, the cumulative amount and the action before it reads the opening, and binds the
    opening to H last (@integraledger/lcp 0.4.1's withinChecks). XS2's opening with its blob one hex digit short, which
    the opening's read refuses xrpl/blob-malformed, is refused for H 0x12 mpp/id-not-ours, for an amount of -1
    mpp/input-malformed, and for a bearer action mpp/session-action; an opening for another H, likewise, gives the
    amount's and the action's codes."""
    xrpl = MPP_SESSION_XRPL
    assert isinstance(xrpl, MppSessionXrpl)
    w = {"challenge": XRPL_OPENING["challenge"], "opening": XRPL_OPENING, "cumulativeAmount": 100, "action": "voucher"}
    short = {**XRPL_OPENING, "payload": {**XRPL_OPENING["payload"], "transaction": HS["XS2"]["blob"][:-1]}}
    broken = {**w, "opening": short}
    assert xrpl.build_within(broken, H) == Refusal("xrpl/blob-malformed")
    assert xrpl.build_within(broken, "0x12") == Refusal("mpp/id-not-ours")
    assert xrpl.build_within({**broken, "cumulativeAmount": -1}, H) == Refusal("mpp/input-malformed")
    action = agreed("an xrpl topUp, use or bearer")
    assert xrpl.build_within({**broken, "action": "bearer"}, H) == Refusal(action)
    assert xrpl.build_within(w, H_OTHER) == Refusal("mpp/id-not-ours")
    assert xrpl.build_within({**w, "cumulativeAmount": -1}, H_OTHER) == Refusal("mpp/input-malformed")
    assert xrpl.build_within({**w, "action": "bearer"}, H_OTHER) == Refusal(action)


# draft-evm-session-00 L1213 and draft-tempo-session-00 L829 at tempoxyz/mpp-specs 08e7dd87: the payload's action is
# one of open, topUp, voucher and close. An action the draft does not define is mpp/session-action from build_within
# as from channel_kind; a topUp, which it defines, is within and is not built.
def test_evm_build_within_refuses_an_action_the_draft_does_not_define_as_channel_kind_does() -> None:
    evm = MPP_SESSION_EVM
    assert isinstance(evm, MppSessionEvm)
    opening = b6(EVM)
    for action in ("use", "bearer"):
        w = {"challenge": opening["challenge"], "opening": opening, "cumulativeAmount": 1, "action": action}
        assert evm.channel_kind({**opening, "payload": {"action": action}}) == Refusal("mpp/session-action")
        assert evm.build_within(w, H) == Refusal("mpp/session-action")
    assert evm.channel_kind({**opening, "payload": {"action": "topUp"}}) == "within"


def test_tempo_build_within_refuses_an_action_the_draft_does_not_define_as_channel_kind_does() -> None:
    tempo = MPP_SESSION_TEMPO
    assert isinstance(tempo, MppSessionTempo)
    opening = tempo_opened().signed
    assert opening is not None
    for action in ("use", "bearer"):
        w = {"challenge": opening["challenge"], "opening": opening, "cumulativeAmount": 1, "action": action}
        assert tempo.channel_kind({**opening, "payload": {"action": action}}) == Refusal("mpp/session-action")
        assert tempo.build_within(w, H) == Refusal("mpp/session-action")
    w = {"challenge": opening["challenge"], "opening": opening, "cumulativeAmount": 1, "action": "topUp"}
    assert tempo.channel_kind({**opening, "payload": {"action": "topUp"}}) == "within"
    assert tempo.build_within(w, H) == Refusal("mpp/within-action-not-built")


# ── the seller's own within challenge on a held Tempo channel.


def own(channel_id: str | None = None, legal_context: str | None = None) -> dict[str, Any]:
    request = json.loads(TF["requestV2"])
    if channel_id is not None:
        request["methodDetails"]["channelId"] = channel_id
    c = {
        "realm": MC["realm"],
        "method": "tempo",
        "intent": "session",
        "request": base64.urlsafe_b64encode(json.dumps(request).encode("utf-8")).decode("ascii").rstrip("="),
        "expires": MC["expires"],
        "id": "sellerOwnChallengeId-0123456789abcdef",
    }
    if legal_context is not None:
        opaque = json.dumps({"legalContext": f"lcp:sha256:{legal_context}", "legalContextUrl": LINK}).encode("utf-8")
        c["opaque"] = base64.urlsafe_b64encode(opaque).decode("ascii").rstrip("=")
    return c


def tempo_hold() -> dict[str, Any]:
    opened = tempo_opened()
    assert opened.signed is not None, opened
    hold = open_channel(STAND_IN, opened.signed, MPP_SESSION_TEMPO)
    assert not isinstance(hold, Declined), hold
    return hold


def wallet() -> Recording:
    return Recording(f"eip155:42431:{TF['payer']}", lambda r: [sign_typed(q["typedData"]) for q in r["requests"]])


CHANNEL = TEMPO["TS3"]["expectChannelId"]


@pytest.mark.parametrize(
    ("channel_id", "legal_context"),
    [(CHANNEL, None), (CHANNEL, H), (None, None)],
    ids=["the held channelId and no legal context", "the held channelId and a legal context naming the held H", "no channelId and no legal context"],
)
def test_the_sellers_own_challenge_is_paid_with_one_voucher_request(channel_id: str | None, legal_context: str | None) -> None:
    hold = tempo_hold()
    challenge = own(channel_id, legal_context)
    signer = wallet()
    out = asyncio.run(within([challenge], hold, MPP_SESSION_TEMPO, signer))
    assert isinstance(out, Within), out
    assert [r["kind"] for r in signer.requests] == ["batch"]
    assert out.signed["challenge"] == challenge
    assert (out.signed["payload"]["action"], out.signed["payload"]["channelId"].lower()) == ("voucher", CHANNEL)


def test_the_sellers_own_challenge_naming_another_channel_declines_before_any_signer_call() -> None:
    hold = tempo_hold()
    signer = wallet()
    out = asyncio.run(within([own("0x" + "22" * 32)], hold, MPP_SESSION_TEMPO, signer))
    assert out == Declined("no-payable-option", "The challenge names a channel this hold did not open.")
    assert signer.requests == []


def test_the_sellers_own_challenge_naming_another_hash_declines_before_any_signer_call() -> None:
    hold = tempo_hold()
    signer = wallet()
    for c in (own(CHANNEL, H_OTHER), own(None, H_OTHER)):
        out = asyncio.run(within([c], hold, MPP_SESSION_TEMPO, signer))
        assert isinstance(out, Declined) and out.code == "hash-mismatch"
    assert signer.requests == []


def test_a_within_challenge_the_tempo_channel_members_refuse_declines_before_any_signer_call() -> None:
    # The seller's own challenge naming the held channel, which build_within reads as the channel members read the
    # voucher carrying it (mpp-challenge.json withinChallenge rows 5 and 7): fixed.requestV1, a v1 challenge over the
    # held v2 channel, and fixed.requestV2 naming another operator, 0x11 repeated, decline offer-unreadable with the
    # members' code.
    v1 = json.loads(TF["requestV1"])
    v1["methodDetails"]["channelId"] = CHANNEL
    other = json.loads(TF["requestV2"])
    other["methodDetails"] |= {"channelId": CHANNEL, "operator": "0x" + "11" * 20}
    hold = tempo_hold()
    for request, code in ((v1, "mpp/not-bound-within"), (other, "tempo/descriptor-mismatch")):
        challenge = {**own(), "request": b64u(json.dumps(request, separators=(",", ":")))}
        signer = wallet()
        out = asyncio.run(within([challenge], hold, MPP_SESSION_TEMPO, signer))
        assert out == Declined("offer-unreadable", code)
        assert signer.requests == []


# ── the within challenge's opaque: MPP's flat string-to-string map (draft-httpauth-payment-01, lines 348-352), read
# as the protocol package reads one: base64url without padding whose final character's unused bits are zero (RFC 4648
# section 3.5), at most 8 KiB decoded, UTF-8 with a leading byte order mark kept as a character. An opaque that is not
# one declines offer-unreadable, mpp/opaque-malformed, before any signer call: buyer.json's BW1 and BW2 opaques among
# them, whose expected decline is that row's.

_LCP = (
    '{"legalContext":"lcp:sha256:' + H + '",'
    '"legalContextUrl":"https://atr.seller.example/7c8acfa2-f800-4192-89e9-1cef9833180f"}'
)


def _seller(size: int) -> str:
    return '{"seller":"' + "x" * (size - 13) + '"}'


# The LCP members and one more: 193 bytes, so the base64url's final character carries unused bits.
_LCP_ODD = _LCP[:-1] + ',"seller":"x"}'
_B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def _bent(text: str) -> str:
    """text's base64url with its final character's lowest unused bit set: the same bytes, written another way."""
    o = base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii").rstrip("=")
    return o[:-1] + _B64URL[_B64URL.index(o[-1]) | 1]


def _with_opaque(text: str, encoded: str | None = None) -> dict[str, Any]:
    c = own(CHANNEL)
    c["opaque"] = encoded if encoded is not None else base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii").rstrip("=")
    return c


@pytest.mark.parametrize(
    ("text", "encoded"),
    [
        ('{"legalContext":null}', None),
        (_LCP[:-1] + ',"seller":1}', None),
        ('{"seller":1}', None),
        ('{"seller":{"a":"b"}}', None),
        ("\ufeff" + _LCP, None),
        ('{"seller":"\\ud800"}', None),
        (_seller(8193), None),
        (_LCP_ODD, _bent(_LCP_ODD)),
    ],
    ids=[
        "BW1: a legalContext member that is null",
        "BW2: the LCP members naming the held H, and a member seller whose value is the number 1",
        "BW2: only a member seller whose value is the number 1",
        "a member whose value is an object",
        "a byte order mark before the object",
        "a member whose value is an escaped lone surrogate, which has no RFC 8785 form",
        "8193 bytes decoded",
        "a final character with a non-zero unused bit, over the LCP members and one more",
    ],
)
def test_an_opaque_that_is_not_a_flat_string_map_declines_before_any_signer_call(text: str, encoded: str | None) -> None:
    hold = tempo_hold()
    signer = wallet()
    out = asyncio.run(within([_with_opaque(text, encoded)], hold, MPP_SESSION_TEMPO, signer))
    assert out == Declined("offer-unreadable", "mpp/opaque-malformed")
    assert signer.requests == []


def test_a_padded_opaque_is_opaque_malformed_and_a_legal_context_not_an_lcp_string_is_legal_context_malformed() -> None:
    hold = tempo_hold()
    signer = wallet()
    padded = base64.urlsafe_b64encode(_LCP.encode("utf-8")).decode("ascii").rstrip("=") + "="
    outs = [
        asyncio.run(within([_with_opaque(_LCP, padded)], hold, MPP_SESSION_TEMPO, signer)),
        asyncio.run(within([_with_opaque('{"legalContext":"not-an-lcp-string"}')], hold, MPP_SESSION_TEMPO, signer)),
    ]
    assert [o.detail if isinstance(o, Declined) else o for o in outs] == ["mpp/opaque-malformed", "mpp/legal-context-malformed"]
    assert signer.requests == []


def test_an_opaque_with_a_non_zero_unused_bit_holds_the_same_bytes_as_its_canonical_form() -> None:
    canonical = base64.urlsafe_b64encode(_LCP_ODD.encode("utf-8")).decode("ascii").rstrip("=")
    assert len(_LCP_ODD.encode("utf-8")) % 3 != 0 and _bent(_LCP_ODD) != canonical
    assert base64.urlsafe_b64decode(_bent(_LCP_ODD) + "=" * (-len(canonical) % 4)) == _LCP_ODD.encode("utf-8")


@pytest.mark.parametrize(
    "text",
    [_seller(8192), _LCP, _LCP_ODD],
    ids=["8192 bytes decoded", "BW1's control naming the held H", "the LCP members and one more, written canonically"],
)
def test_an_opaque_of_at_most_8_kib_is_read_with_one_voucher_request(text: str) -> None:
    assert len(text.encode("utf-8")) <= 8192
    hold = tempo_hold()
    signer = wallet()
    out = asyncio.run(within([_with_opaque(text)], hold, MPP_SESSION_TEMPO, signer))
    assert isinstance(out, Within), out
    assert [r["kind"] for r in signer.requests] == ["batch"]


# ── inChannelSize (mpp-challenge.json): build_within's complete measures the in-channel credential, and the pairing's
# channel_kind, channel_ref and bound_within measure the payment they are given, with credentialSize's bound and code.
# The within challenge is the opening's challenge as issued with the id seller-own-id (mpp-session-within.test.ts in
# @integraledger/lcp 0.4.1), padded by a description so that the in-channel credential measures the row's size.

IN_CHANNEL = load("mpp-challenge.json")["inChannelSize"]["rows"]


def _in_channel_set_ups() -> dict[str, tuple[Any, dict[str, Any], dict[str, Any], int, str]]:
    """Each session with a build_within: its binding, the opening, the within challenge, the cumulative amount and one
    signature of the pairing's form."""
    sig = "0x" + "11" * 65
    tempo = tempo_opened().signed
    assert tempo is not None
    within = {
        "evm": issued("evm", "session", EVM["fixed"]["request"]),
        "tempo": issued("tempo", "session", TF["requestV2"]),
        "xrpl": HS["SS1"]["xrpl"]["challenge"],
    }
    w = {rail: {**c, "id": "seller-own-id"} for rail, c in within.items()}
    return {
        "mpp/session/evm": (MPP_SESSION_EVM, b6(EVM), w["evm"], 250, sig),
        "mpp/session/tempo": (MPP_SESSION_TEMPO, tempo, w["tempo"], 250, sig),
        "mpp/session/xrpl": (MPP_SESSION_XRPL, XRPL_OPENING, w["xrpl"], 100, "C0" * 64),
    }


WITHIN_SESSIONS = [f"mpp/session/{rail}" for rail in ("evm", "tempo", "xrpl")]


@pytest.mark.parametrize("pairing", WITHIN_SESSIONS)
def test_in_channel_size_build_within_and_the_channel_members_measure_the_in_channel_credential(pairing: str) -> None:
    from credential_size import described, description_for, size_of

    binding, opening, within, amount, signature = _in_channel_set_ups()[pairing]

    def complete(challenge: dict[str, Any]) -> Any:
        w = {"challenge": challenge, "opening": opening, "cumulativeAmount": amount, "action": "voucher"}
        unsigned = binding.build_within(w, H)
        assert isinstance(unsigned, BatchUnsigned), unsigned
        return unsigned.complete([signature])

    def answers(c: Any) -> list[Any]:
        return [binding.channel_kind(c), binding.channel_ref(c), binding.bound_within(c)]

    plain = complete(within)
    assert not isinstance(plain, Refusal), plain
    taken = answers(plain)
    assert len(IN_CHANNEL) == 3
    for row in IN_CHANNEL:
        challenge = described(within, description_for(plain, row["size"]))
        sized = {**plain, "challenge": challenge}
        assert size_of(sized) == row["size"], row["case"]
        made = complete(challenge)
        if row.get("taken"):
            assert made == sized, row["case"]
            assert answers(sized) == taken, row["case"]
        else:
            assert made == Refusal(row["expect"]), row["case"]
            assert answers(sized) == [Refusal(row["expect"])] * 3, row["case"]


# ── withinChallenge (mpp-challenge.json): build_within reads the within challenge as the pairing's channel_kind,
# channel_ref and bound_within read the payment that carries it, with their code for each fault, from the snapshot of
# its own members that the in-channel credential carries; and it gives a reader's code where that reader refuses a
# payment whose within challenge names channel parameters other than the opening's (mpp-session-within.test.ts in
# @integraledger/lcp 0.4.1). The set-ups are the rows' about's: the openings are B6's on the EVM session, build's of
# fixed.requestV2 and fixed.requestV1 on the Tempo session, and that of SS1's placed challenge (XS2) on the XRPL
# session; the within challenge is the opening's challenge as issued, with the id
# seller-own-id.

WITHIN_CHALLENGE = load("mpp-challenge.json")["withinChallenge"]["rows"]
WITHIN_ROWS = {
    "mpp/session/evm": 2,
    "mpp/session/tempo": 8,
    "mpp/session/xrpl": 2,
}


def issued_of(c: dict[str, Any]) -> dict[str, Any]:
    """A placed challenge as the seller issues it within the channel: no opaque, and the seller's own id."""
    return {**{k: v for k, v in c.items() if k not in ("id", "opaque")}, "id": "seller-own-id"}


@functools.cache
def _tempo_openings() -> dict[str, dict[str, Any]]:
    from test_mpp_session import tempo_opening

    return {"v2": tempo_opening(TF["requestV2"], TF["chainId"]), "v1": tempo_opening(TF["requestV1"], TF["chainId"])}


SetUp = tuple[Any, dict[str, Any], dict[str, Any], dict[str, Any], str]


def _within_set_up(pairing: str, opening: str = "v2", within: str | None = None) -> SetUp:
    """The pairing's binding, its opening, the within challenge of the opening's request (the control) and of the
    row's (on the Tempo session, the opening of the row's within protocol), and one signature of the pairing's form."""
    sig = "0x" + "11" * 65
    if pairing == "mpp/session/tempo":
        openings = _tempo_openings()
        held = openings[opening]
        row_within = issued_of(openings[within or opening]["challenge"])
        return MPP_SESSION_TEMPO, held, issued_of(held["challenge"]), row_within, sig
    binding, held, signature = {
        "mpp/session/evm": (MPP_SESSION_EVM, b6(EVM), sig),
        "mpp/session/xrpl": (MPP_SESSION_XRPL, XRPL_OPENING, "C0" * 64),
    }[pairing]
    return binding, held, issued_of(held["challenge"]), issued_of(held["challenge"]), signature


def _request_of(c: dict[str, Any]) -> dict[str, Any]:
    text = c["request"]
    request: dict[str, Any] = json.loads(base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)))
    return request


def _with_request(c: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    return {**c, "request": b64u(json.dumps(request, separators=(",", ":")))}


def changed(within: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    """The within challenge with the row's change: its request; methodDetails' members; one member dropped from
    methodDetails; or no id."""
    if "id" in row:
        return {k: v for k, v in within.items() if k != "id"}
    if "request" in row:
        return {**within, "request": row["request"]}
    if "methodDetails" not in row and "drop" not in row:
        return within
    r = _request_of(within)
    details = {**r["methodDetails"], **row.get("methodDetails", {})}
    details.pop(row.get("drop", ""), None)
    return _with_request(within, {**r, "methodDetails": details})


def _within_rows(pairing: str) -> list[dict[str, Any]]:
    rows = [r for r in WITHIN_CHALLENGE if r["pairing"] == pairing]
    assert len(rows) == WITHIN_ROWS[pairing], (pairing, len(rows))
    return rows


def test_within_challenge_rows_are_the_sessions_with_a_build_within() -> None:
    assert {r["pairing"] for r in WITHIN_CHALLENGE} == set(WITHIN_ROWS)


@pytest.mark.parametrize(
    "row", [r for p in WITHIN_ROWS for r in _within_rows(p)], ids=lambda r: f"{r['pairing']}: {r['case']}"
)
def test_within_challenge_build_within_reads_it_as_the_channel_members_do(row: dict[str, Any]) -> None:
    set_up = _within_set_up(row["pairing"], row.get("opening", "v2"), row.get("within"))
    binding, opening, control, within_challenge, signature = set_up

    def w(c: dict[str, Any]) -> dict[str, Any]:
        return {"challenge": c, "opening": opening, "cumulativeAmount": 100, "action": row.get("action", "voucher")}

    def answers(c: Any) -> list[Any]:
        return [binding.channel_kind(c), binding.channel_ref(c), binding.bound_within(c)]

    unsigned = binding.build_within(w(control), H)
    assert isinstance(unsigned, BatchUnsigned), unsigned
    plain = unsigned.complete([signature])
    assert not isinstance(plain, Refusal), plain
    taken = answers(plain)
    c = changed(within_challenge, row)
    assert c != control
    code = Refusal(row["expect"])
    assert binding.build_within(w(c), H) == code
    read = answers({**plain, "challenge": c})
    assert code in read
    for i, answer in enumerate(read):
        assert answer in (taken[i], code), (i, answer)


@pytest.mark.parametrize("pairing", WITHIN_SESSIONS)
def test_a_within_challenge_naming_the_channel_builds_as_the_channel_members_take_it(pairing: str) -> None:
    # The seller's within challenge names the channel it resumes; the pairing's filter refuses a challenge naming a
    # channel (mpp/channel-named), and build_within does not hold the within challenge to it.
    binding, opening, control, _, signature = _within_set_up(pairing)

    def complete(c: dict[str, Any]) -> Any:
        w = {"challenge": c, "opening": opening, "cumulativeAmount": 100, "action": "voucher"}
        unsigned = binding.build_within(w, H)
        assert isinstance(unsigned, BatchUnsigned), unsigned
        return unsigned.complete([signature])

    def answers(c: Any) -> list[Any]:
        return [binding.channel_kind(c), binding.channel_ref(c), binding.bound_within(c)]

    plain = complete(control)
    channel = plain["payload"]["channelId"]
    r = _request_of(control)
    if pairing == "mpp/session/xrpl":
        named = _with_request(control, {**r, "channelId": channel})
    else:
        named = _with_request(control, {**r, "methodDetails": {**r["methodDetails"], "channelId": channel}})
    made = complete(named)
    assert made == {**plain, "challenge": named}
    assert answers(made) == answers(plain)
    assert pairings_of(named) == Refusal("mpp/channel-named")


def _nested(n: int) -> Any:
    return "x" if n == 0 else [_nested(n - 1)]


@pytest.mark.parametrize("pairing", WITHIN_SESSIONS)
def test_build_within_holds_the_within_challenge_s_own_members_within_the_credential_bounds(pairing: str) -> None:
    # build_within holds the within challenge as the channel members read the payment that carries it: the least
    # credential echoing it, {challenge, payload: {}}, within the credential size bound; one at the bound builds and its
    # in-channel credential is over the bound, and one over it is refused. A member that is not one of MPP's challenge
    # members is not in the snapshot, so the credential is the one without it; on the credential echoing it,
    # channel_kind takes one 16 arrays and objects deep and refuses one 17 deep (mpp-session-within.test.ts in
    # @integraledger/lcp 0.4.1).
    from credential_size import described, description_for, size_of

    binding, opening, control, _, signature = _within_set_up(pairing)

    def w(c: dict[str, Any]) -> dict[str, Any]:
        return {"challenge": c, "opening": opening, "cumulativeAmount": 100, "action": "voucher"}

    def built(c: dict[str, Any]) -> Any:
        unsigned = binding.build_within(w(c), H)
        assert isinstance(unsigned, BatchUnsigned), unsigned
        return unsigned.complete([signature])

    malformed = Refusal("mpp/credential-malformed")
    plain = built(control)
    least = {"challenge": control, "payload": {}}
    at = described(control, description_for(least, 65_536))
    over = described(control, description_for(least, 65_537))
    assert [size_of({"challenge": at, "payload": {}}), size_of({"challenge": over, "payload": {}})] == [65_536, 65_537]
    assert built(at) == malformed
    assert binding.build_within(w(over), H) == malformed
    assert not isinstance(binding.channel_kind(plain), Refusal)
    for n, depth in ((14, 16), (15, 17)):
        deep = {**control, "deep": _nested(n)}
        assert built(deep) == plain
        kind = binding.channel_kind({**plain, "challenge": deep})
        assert (kind == malformed) == (depth == 17), (depth, kind)


@pytest.mark.parametrize("pairing", WITHIN_SESSIONS)
def test_build_within_reads_the_within_challenge_before_h_the_amount_the_action_and_the_opening(pairing: str) -> None:
    # @integraledger/lcp 0.4.1's withinChecks order: the within challenge's snapshot, its least credential's size, its
    # intent and method, and the readers' read of its request, each before H, the amount, the action and the opening.
    # Each input carries a fault of every later check too, and gives the earliest check's code.
    binding, _, control, _, _ = _within_set_up(pairing)
    later = {"opening": {"challenge": control, "payload": {}}, "cumulativeAmount": -1, "action": "bearer"}
    method = {**control, "method": "lightning"}
    read = {**control, "request": "!!"}
    no_id = {k: v for k, v in method.items() if k != "id"}
    assert binding.build_within({**later, "challenge": read}, "0x12") == Refusal("mpp/request-malformed")
    not_this = {**method, "request": "!!"}
    assert binding.build_within({**later, "challenge": not_this}, "0x12") == Refusal("mpp/not-this-pairing")
    assert binding.build_within({**later, "challenge": no_id}, "0x12") == Refusal("mpp/credential-malformed")
    assert binding.build_within({**later, "challenge": 5}, "0x12") == Refusal("mpp/credential-malformed")
