"""The in-channel payment of MPP's sessions: build_within of each session binding, so the Python gate's within
serves MPP sessions as the TypeScript gate's does; and the within challenge the seller issues itself on a live
channel, with its own id and the channel named in methodDetails.channelId: the gate signs only for a channel it opened
for an ATR it compared, and only when the within challenge's legal context is absent or names that H. The voucher
digests and bytes are the vector files' (ES5, TS4, HS2, SV3 on SV2's opening, XS3 on XS2's); the within challenges are
the issued request with methodDetails.channelId added, a fresh id, and no opaque unless a legal context is given. The
TypeScript gate's tests are channels.test.ts's."""

import asyncio
import base64
import json
from typing import Any

import pytest

from integraledger_terms import (
    MPP_SESSION_EVM,
    MPP_SESSION_HEDERA,
    MPP_SESSION_SOLANA,
    MPP_SESSION_TEMPO,
    MPP_SESSION_XRPL,
    Declined,
    Transacted,
    Within,
    _gate,
    open_channel,
    transact,
    within,
)
from integraledger_terms._types import Refusal
from integraledger_terms.bindings._channel import BatchUnsigned
from integraledger_terms.bindings._svm import PAYMENT_CHANNELS, key_bytes
from integraledger_terms.bindings.mpp_session import MppSessionEvm, MppSessionTempo
from integraledger_terms.bindings.mpp_session_hedera import MppSessionHedera
from integraledger_terms.bindings.mpp_session_xrpl import MppSessionXrpl

from breadth import ABC, H, LINK, Recording, offered, run
from mpp_docs import issued, placed_doc
from support import digest, load, serving, sign_typed

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


def build(binding: Any, opening: dict[str, Any], amount: int) -> BatchUnsigned:
    w = {"challenge": opening["challenge"], "opening": opening, "cumulativeAmount": amount, "action": "voucher"}
    unsigned = binding.build_within(w, H)
    assert isinstance(unsigned, BatchUnsigned), unsigned
    return unsigned


# ── build_within against the vectors' voucher digests.


def test_evm_build_within_at_zero_is_es5s_voucher() -> None:
    unsigned = build(MPP_SESSION_EVM, b6(EVM), 0)
    assert [r["kind"] for r in unsigned.requests] == ["eip712"]
    assert digest(unsigned.requests[0]["typedData"]) == EVM["ES5"]["expectVoucherDigest"]


def tempo_opened() -> Transacted:
    doc = placed_doc(issued("tempo", "session", TF["requestV2"]), H, LINK)
    from test_mpp_session import TempoAnswer

    out = run(lambda c: transact(doc, MPP_SESSION_TEMPO, Recording(f"eip155:42431:{TF['payer']}", TempoAnswer()), c, inputs={"deposit": TF["deposit"]}), serving(ABC))
    assert isinstance(out, Transacted) and out.signed is not None, out
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


def hedera_opened() -> Transacted:
    doc = placed_doc(HS["SS1"]["hedera"]["challenge"], H, LINK)
    signer = Recording(
        f"hedera:testnet:{HS['fixed']['payer']}",
        lambda r: {
            "openTx": HS["HS3"]["txHash"],
            "signature": sign_typed(r["voucher"]),
            "landed": {"transaction": HS["HS3"]["txHash"], "blockNumber": "1", "logs": [HS["HS3"]["log"]]},
        },
    )
    out = run(lambda c: transact(doc, offered(MPP_SESSION_HEDERA), signer, c, inputs={"deposit": HS["HS2"]["deposit"]}), serving(ABC))
    assert isinstance(out, Transacted), out
    return out


def test_hedera_build_within_at_zero_is_hs2s_voucher() -> None:
    opening = hedera_opened().signed
    assert opening is not None
    assert digest(build(MPP_SESSION_HEDERA, opening, 0).requests[0]["typedData"]) == HS["HS2"]["expectVoucherDigest"]


def compact(signature: str) -> str:
    """EIP-2098's 64-byte form of a 65-byte r ‖ s ‖ v signature: r, then s with the y parity (v - 27) in its top bit."""
    raw = bytes.fromhex(signature[2:])
    assert len(raw) == 65 and raw[64] in (27, 28), signature
    vs = int.from_bytes(raw[32:64], "big") | (raw[64] - 27) << 255
    return "0x" + raw[:32].hex() + vs.to_bytes(32, "big").hex()


def test_hedera_refuses_an_action_the_draft_does_not_define_as_channel_kind_does() -> None:
    # draft-hedera-session-00 L840-845 at tempoxyz/mpp-specs 08e7dd87, as the session file's row cites it: the
    # payload's action is one of open, topUp, voucher and close. A use or a bearer is mpp/session-action from
    # channel_kind, channel_ref and build_within; a topUp, which it defines, is within and is not built.
    hedera = MPP_SESSION_HEDERA
    assert isinstance(hedera, MppSessionHedera)
    code = agreed("a hedera use")
    placed = HS["SS1"]["hedera"]["placed"]
    opening = {"challenge": placed, "payload": {"action": "open", "channelId": HS["HS1"]["expectChannelId"], "txHash": HS["HS3"]["txHash"], "cumulativeAmount": "0", "signature": "0x00"}}
    for action in ("use", "bearer"):
        presented = {"challenge": placed, "payload": {"action": action, "channelId": HS["HS1"]["expectChannelId"]}}
        assert hedera.channel_kind(presented) == Refusal(code)
        assert hedera.channel_ref(presented) == Refusal(code)
        w = {"challenge": placed, "opening": opening, "cumulativeAmount": 1, "action": action}
        assert hedera.build_within(w, H) == Refusal(code)
    top_up = {"challenge": placed, "payload": {"action": "topUp", "channelId": HS["HS1"]["expectChannelId"]}}
    assert hedera.channel_kind(top_up) == "within"
    w = {"challenge": placed, "opening": opening, "cumulativeAmount": 1, "action": "topUp"}
    assert hedera.build_within(w, H) == Refusal("mpp/within-action-not-built")


def test_hedera_within_complete_takes_a_signature_of_one_byte_or_more() -> None:
    # The voucher is signed by the payer and passed on unverified, as the other MPP completes do: EIP-2098's 64-byte form
    # of the voucher's signature is a signature too, and one of no bytes is not (@integraledger/lcp's buildWithin).
    opening = hedera_opened().signed
    assert opening is not None
    unsigned = build(MPP_SESSION_HEDERA, opening, 25)
    signature = sign_typed(unsigned.requests[0]["typedData"])
    for answer in (signature, compact(signature), "0x11"):
        out = unsigned.complete([answer])
        assert isinstance(out, dict) and out["payload"]["signature"] == answer, (answer, out)
    for answer in ("0x", "11", "0x1", "0xzz"):
        assert (answer, unsigned.complete([answer])) == (answer, Refusal("mpp/credential-malformed"))


SOLANA_OPENING = {
    "challenge": HS["SS1"]["solana"]["placed"],
    "payload": {"action": "open", "channelId": HS["SV2"]["channel"], "transaction": HS["SV2"]["wireBase64"]},
}
XRPL_OPENING = {
    "challenge": HS["SS1"]["xrpl"]["placed"],
    "payload": {"action": "open", "transaction": HS["XS2"]["blob"], "amount": "100", "signature": "00"},
}


def test_solana_build_within_at_100_is_sv3s_voucher_for_the_opening_s_signer() -> None:
    unsigned = build(MPP_SESSION_SOLANA, SOLANA_OPENING, 100)
    assert unsigned.requests == [
        {"kind": "ed25519-raw", "message": bytes.fromhex(HS["SV3"]["expectVoucher"]), "signer": HS["SV3"]["payer"]}
    ]
    signature = "1" * 64
    credential = unsigned.complete([signature])
    channel = HS["SV2"]["channel"]
    assert credential == {
        "challenge": SOLANA_OPENING["challenge"],
        "payload": {
            "action": "voucher",
            "channelId": channel,
            "voucher": {
                "voucher": {"channelId": channel, "cumulativeAmount": "100"},
                "signer": HS["SV3"]["payer"],
                "signature": signature,
                "signatureType": "ed25519",
            },
        },
    }
    assert unsigned.complete(["0x" + "11" * 64]) == Refusal("mpp/credential-malformed")


def with_a_short_channel_instruction(wire_b64: str) -> str:
    """The wire with one more top-level instruction to the channel program before the others: six accounts, account 4
    static key 0, and the open discriminator as its only data byte, shorter than an open. The message's key and
    instruction counts are below 128, so each is one byte (Solana's compact-u16); no signature is read here."""
    wire = base64.b64decode(wire_b64)
    signed = 1 + 64 * wire[0]
    message = wire[signed:]
    keys = message[4]
    assert message[0] == 0x80 and keys < 128
    channel_program = key_bytes(PAYMENT_CHANNELS)
    assert channel_program is not None
    program = [message[5 + 32 * k : 37 + 32 * k] for k in range(keys)].index(channel_program)
    at = 5 + 32 * keys + 32
    assert message[at] < 127
    short = bytes([program, 6, 1, 1, 1, 1, 0, 1, 1, 1])
    return base64.b64encode(wire[:signed] + message[:at] + bytes([message[at] + 1]) + short + message[at + 1 :]).decode()


def test_solana_build_within_names_the_signer_of_the_opening_s_one_open() -> None:
    # The opening's open is its one instruction to the channel program with an open's data and accounts: an
    # instruction before it that only starts with the open discriminator is not an open, and its account 4 does not
    # sign the voucher. The voucher's signer is SV2's open's authorizedSigner, SV3's payer.
    wire = with_a_short_channel_instruction(HS["SV2"]["wireBase64"])
    opening = {**SOLANA_OPENING, "payload": {**SOLANA_OPENING["payload"], "transaction": wire}}
    assert MPP_SESSION_SOLANA.bound(opening) == H
    unsigned = build(MPP_SESSION_SOLANA, opening, 100)
    assert unsigned.requests == [
        {"kind": "ed25519-raw", "message": bytes.fromhex(HS["SV3"]["expectVoucher"]), "signer": HS["SV3"]["payer"]}
    ]


def test_solana_build_within_refuses_an_operator_channel_s_voucher() -> None:
    placed = dict(HS["SS1"]["solana"]["placed"])
    text = placed["request"]
    request = json.loads(base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)))
    request["methodDetails"].update(HS["SV5"]["methodDetails"])
    placed["request"] = base64.urlsafe_b64encode(json.dumps(request).encode("utf-8")).decode("ascii").rstrip("=")
    # SV5.opening, whose account 4 is the challenge's operator, with the authentication operator mode requires.
    authentication = {**HS["SV5"]["expectAuthentication"], "challengeId": placed["id"], "signature": "x"}
    payload = {"action": "open", "channelId": HS["SV5"]["opening"]["channel"], "transaction": HS["SV5"]["opening"]["wireBase64"], "authentication": authentication}
    opening = {"challenge": placed, "payload": payload}
    w = {"challenge": placed, "opening": opening, "cumulativeAmount": 100, "action": "voucher"}
    assert MPP_SESSION_SOLANA.build_within(w, H) == Refusal("mpp/within-action-not-built")


def agreed(prefix: str) -> str:
    """The code of the one agreedRefusals row of the session file whose case starts with prefix."""
    codes = [r["expect"] for r in HS["agreedRefusals"]["rows"] if r["case"].startswith(prefix)]
    assert len(codes) == 1, (prefix, codes)
    found: str = codes[0]
    return found


def test_solana_build_within_refuses_a_bearer_as_channel_kind_does() -> None:
    # draft-solana-session-00 defines open, voucher, use, topUp and close: build_within builds a voucher and a close,
    # refuses a topUp or a use as not built, and refuses an action the draft does not define with channel_kind's code.
    code = agreed("a solana bearer")
    w = {"challenge": SOLANA_OPENING["challenge"], "opening": SOLANA_OPENING, "cumulativeAmount": 100, "action": "bearer"}
    assert MPP_SESSION_SOLANA.build_within(w, H) == Refusal(code)
    bearer = {"challenge": SOLANA_OPENING["challenge"], "payload": {"action": "bearer", "channelId": HS["SV2"]["channel"]}}
    assert MPP_SESSION_SOLANA.channel_kind(bearer) == Refusal(code)
    for action in ("topUp", "use"):
        assert MPP_SESSION_SOLANA.build_within({**w, "action": action}, H) == Refusal("mpp/within-action-not-built")


def test_xrpl_build_within_at_100_is_xs3s_claim_on_xs2s_channel() -> None:
    unsigned = build(MPP_SESSION_XRPL, XRPL_OPENING, int(HS["XS3"]["drops"]))
    channel = HS["XS2"]["expectChannel"]
    assert unsigned.requests == [
        {"kind": "xrpl-claim", "channelId": channel, "drops": int(HS["XS3"]["drops"]), "bytes": bytes.fromhex(HS["XS3"]["expect"])}
    ]
    assert unsigned.complete(["C0" * 64]) == {
        "challenge": XRPL_OPENING["challenge"],
        "payload": {"action": "voucher", "channelId": channel, "amount": HS["XS3"]["drops"], "signature": "C0" * 64},
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
    hold = open_channel(opened.atr_bytes, opened.signed, MPP_SESSION_TEMPO)
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


# ── the held Hedera session pays the seller's own within challenge (its own id, no legal context).


def test_a_held_hedera_session_pays_the_sellers_own_challenge() -> None:
    opened = hedera_opened()
    assert opened.signed is not None, opened
    hold = open_channel(opened.atr_bytes, opened.signed, MPP_SESSION_HEDERA, opened.landed)
    assert not isinstance(hold, Declined), hold
    challenge = {k: v for k, v in HS["SS1"]["hedera"]["challenge"].items() if k != "opaque"}
    challenge["id"] = "sellerOwnChallengeId-0123456789abcdef"
    signer = Recording(hold["network"], lambda r: [sign_typed(q["typedData"]) for q in r["requests"]])
    out = asyncio.run(within([challenge], hold, MPP_SESSION_HEDERA, signer))
    assert isinstance(out, Within), out
    assert [r["kind"] for r in signer.requests] == ["batch"]
    assert (out.signed["payload"]["action"], out.signed["payload"]["channelId"]) == ("voucher", HS["HS1"]["expectChannelId"])
