"""bound and the channel members start from the echoed challenge's H (challenge_bound) and read, and check, only the
request members their own read keys or derivation use; the request's other checks are pairings_of's and the build's.
Each credential is a vector file's B6 row as it presents it, whose expected H is that row's; the request is re-encoded
as base64url of its RFC 8785 JSON after each change. Each expected refusal is the protocol package's answer to the same
credential, as its own test of these reads (lcp 0.4.0, test/mpp-echoed-request.test.ts) records it."""

import copy
import json
from collections.abc import Callable
from typing import Any

import pytest

import integraledger_terms as terms
from integraledger_terms import Refusal
from integraledger_terms.bindings._codec import b64u_decode, b64u_encode, canonical_json
from integraledger_terms.bindings._mpp import pairings_of
from integraledger_terms.bindings._mpp_checks import hedera_charge_network
from integraledger_terms.bindings.mpp_charge_usdc import gateway_account, usdc_gateway_salt, usdc_request_hash

from support import load

Edit = Callable[[dict[str, Any], dict[str, Any]], None]

BINDINGS: dict[str, Any] = {
    v.id: v for n in dir(terms) if n.isupper() and hasattr(v := getattr(terms, n), "id") and hasattr(v, "bound")
}
FILES = {
    "mpp/charge/evm/authorization": "mpp-charge-evm-authorization.json",
    "mpp/charge/evm/permit2": "mpp-charge-evm-permit2.json",
    "mpp/charge/tempo/memo": "mpp-charge-tempo-memo.json",
    "mpp/charge/tempo/push": "mpp-charge-tempo-push.json",
    "mpp/charge/solana": "mpp-charge-solana.json",
    "mpp/charge/stellar": "mpp-charge-stellar.json",
    "mpp/charge/xrpl": "mpp-charge-xrpl.json",
    "mpp/charge/nearintents": "mpp-charge-nearintents.json",
    "mpp/charge/usdc/evm": "mpp-charge-usdc-evm.json",
    "mpp/charge/usdc/solana": "mpp-charge-usdc-solana.json",
    "mpp/charge/usdc/stacks": "mpp-charge-usdc-stacks.json",
    "mpp/charge/usdc/gateway": "mpp-charge-usdc-gateway.json",
    "mpp/session/evm": "mpp-session-evm.json",
    "mpp/session/tempo": "mpp-session-tempo.json",
    "mpp/session/hedera": "mpp-session-hedera-solana-xrpl.json",
    "mpp/session/solana": "mpp-session-hedera-solana-xrpl.json",
    "mpp/session/xrpl": "mpp-session-hedera-solana-xrpl.json",
    "mpp/subscription/tempo": "mpp-subscription-tempo.json",
}
CHANNELS = ("mpp/session/evm", "mpp/session/tempo", "mpp/session/hedera", "mpp/session/solana", "mpp/session/xrpl")


def b6(pairing: str) -> dict[str, Any]:
    rows = [r for r in load(FILES[pairing])["buyer"]["rows"] if r["name"] == "B6" and r["pairing"] == pairing]
    assert len(rows) == 1, pairing
    row: dict[str, Any] = rows[0]
    return row


def expected_h(pairing: str) -> str:
    h: str = b6(pairing)["expect"][0]["h"]
    return h


def no_edit(r: dict[str, Any], c: dict[str, Any]) -> None:
    pass


def presented(pairing: str, edit: Edit = no_edit) -> dict[str, Any]:
    """The pairing's B6 credential, with edit applied to its decoded request and its challenge."""
    c: dict[str, Any] = copy.deepcopy(b6(pairing)["input"]["presented"])
    request = request_of(c)
    edit(request, c["challenge"])
    c["challenge"]["request"] = b64u_encode(canonical_json(request).encode("utf-8"))
    return c


def request_of(c: dict[str, Any]) -> dict[str, Any]:
    raw = b64u_decode(c["challenge"]["request"], 8192)
    assert raw is not None
    request: dict[str, Any] = json.loads(raw)
    return request


def offer_of(c: dict[str, Any]) -> dict[str, Any]:
    """The challenge as the seller issued it, before the placement: no id and no opaque."""
    return {k: v for k, v in c["challenge"].items() if k not in ("id", "opaque")}


def bound(pairing: str, c: dict[str, Any]) -> Any:
    return BINDINGS[pairing].bound(copy.deepcopy(c))


def channel_ref(pairing: str, c: dict[str, Any]) -> Any:
    return BINDINGS[pairing].channel_ref(copy.deepcopy(c))


def details(r: dict[str, Any]) -> dict[str, Any]:
    md: dict[str, Any] = r["methodDetails"]
    return md


def no_expires(r: dict[str, Any], c: dict[str, Any]) -> None:
    del c["expires"]


def expires_not_a_date(r: dict[str, Any], c: dict[str, Any]) -> None:
    c["expires"] = "tomorrow"


def method_details_5(r: dict[str, Any], c: dict[str, Any]) -> None:
    r["methodDetails"] = 5


def both(*edits: Edit) -> Edit:
    def apply(r: dict[str, Any], c: dict[str, Any]) -> None:
        for e in edits:
            e(r, c)

    return apply


def member(key: str, value: Any) -> Edit:
    return lambda r, c: r.__setitem__(key, value)


def without(key: str) -> Edit:
    return lambda r, c: r.pop(key)


def detail(key: str, value: Any) -> Edit:
    return lambda r, c: details(r).__setitem__(key, value)


def without_detail(key: str) -> Edit:
    return lambda r, c: details(r).pop(key)


UNREAD: list[tuple[str, str, Edit]] = [
    ("charge/evm/authorization, no expires", "mpp/charge/evm/authorization", no_expires),
    ('charge/evm/authorization, amount "abc"', "mpp/charge/evm/authorization", member("amount", "abc")),
    ("charge/evm/permit2, externalId null", "mpp/charge/evm/permit2", member("externalId", None)),
    ('charge/tempo/memo, amount "abc"', "mpp/charge/tempo/memo", member("amount", "abc")),
    ("charge/tempo/push, no expires", "mpp/charge/tempo/push", no_expires),
    ("charge/solana, no expires", "mpp/charge/solana", no_expires),
    ('charge/stellar, amount "0"', "mpp/charge/stellar", member("amount", "0")),
    ("charge/xrpl, no expires", "mpp/charge/xrpl", no_expires),
    ('charge/nearintents, amount "x"', "mpp/charge/nearintents", member("amount", "x")),
    ("charge/usdc/evm, no expires", "mpp/charge/usdc/evm", no_expires),
    ("charge/usdc/solana, no expires", "mpp/charge/usdc/solana", no_expires),
    ("charge/usdc/stacks, no expires", "mpp/charge/usdc/stacks", no_expires),
    ("charge/usdc/gateway, no expires", "mpp/charge/usdc/gateway", no_expires),
    (
        'session/evm, no expires and credentialTypes ["other"]',
        "mpp/session/evm",
        both(no_expires, detail("credentialTypes", ["other"])),
    ),
    ('session/tempo, amount "abc"', "mpp/session/tempo", member("amount", "abc")),
    ("session/solana, no expires", "mpp/session/solana", no_expires),
    ('session/xrpl, no expires and currency "USD"', "mpp/session/xrpl", both(no_expires, member("currency", "USD"))),
    (
        'subscription/tempo, periodCount "0", periodUnit "month", subscriptionExpires "tomorrow", amount "abc", '
        "no expires",
        "mpp/subscription/tempo",
        both(
            member("periodCount", "0"),
            member("periodUnit", "month"),
            member("subscriptionExpires", "tomorrow"),
            member("amount", "abc"),
            no_expires,
        ),
    ),
]


@pytest.mark.parametrize(("name", "pairing", "edit"), UNREAD, ids=[n for n, _, _ in UNREAD])
def test_bound_reads_no_request_member_it_does_not_use(name: str, pairing: str, edit: Edit) -> None:
    assert bound(pairing, presented(pairing)) == expected_h(pairing)
    assert bound(pairing, presented(pairing, edit)) == expected_h(pairing)


@pytest.mark.parametrize("pairing", sorted(FILES))
def test_bound_does_not_read_expires(pairing: str) -> None:
    assert bound(pairing, presented(pairing, expires_not_a_date)) == expected_h(pairing)


def test_a_usdc_credential_is_read_only_by_the_pairing_of_the_profile_its_method_details_type_names() -> None:
    c = presented("mpp/charge/usdc/evm")
    assert BINDINGS["mpp/charge/usdc/gateway"].bound(c) == Refusal("mpp/not-this-pairing")


# A request's methodDetails is an object (draft-payment-intent-charge-00, Table 3: "methodDetails | object |
# Method-specific extension data"); pairings_of refuses one that is not with mpp/request-malformed.
@pytest.mark.parametrize("pairing", sorted(FILES))
def test_a_method_details_that_is_not_an_object_is_request_malformed_never_read_as_empty(pairing: str) -> None:
    c = presented(pairing, method_details_5)
    assert pairings_of(offer_of(c)) == Refusal("mpp/request-malformed")
    assert bound(pairing, c) == Refusal("mpp/request-malformed")
    if pairing in CHANNELS:
        assert channel_ref(pairing, c) == Refusal("mpp/request-malformed")


def test_the_hedera_charge_network_refuses_a_method_details_that_is_not_an_object() -> None:
    assert hedera_charge_network({"methodDetails": 5}, "hedera:testnet") == Refusal("mpp/request-malformed")
    assert hedera_charge_network({}, "hedera:testnet") == "hedera:testnet"


# The request member that carries H is read as pairings_of reads it: externalId is a string ("externalId | string |
# OPTIONAL", draft-nearintents-charge-01), on Solana one that "MUST NOT exceed 566 bytes (Solana Memo Program limit)"
# (draft-solana-charge-00), which usdc's Solana profile inherits (draft-usdc-charge-00); the XRP Ledger's invoiceId is
# 64 hex digits (draft-xrpl-charge-00). Absent, it is the member's own refusal: the signed carrier differs.
CARRIERS: list[tuple[str, str, Edit]] = [
    ("charge/solana, externalId 5", "mpp/charge/solana", member("externalId", 5)),
    ("charge/solana, externalId of 567 bytes", "mpp/charge/solana", member("externalId", "x" * 567)),
    ("charge/usdc/solana, externalId 5", "mpp/charge/usdc/solana", member("externalId", 5)),
    ("charge/usdc/solana, externalId of 567 bytes", "mpp/charge/usdc/solana", member("externalId", "x" * 567)),
    ("charge/nearintents, externalId 5", "mpp/charge/nearintents", member("externalId", 5)),
    ("charge/xrpl, invoiceId 5", "mpp/charge/xrpl", detail("invoiceId", 5)),
    ('charge/xrpl, invoiceId "0x12"', "mpp/charge/xrpl", detail("invoiceId", "0x12")),
]


@pytest.mark.parametrize(("name", "pairing", "edit"), CARRIERS, ids=[n for n, _, _ in CARRIERS])
def test_a_malformed_carrier_is_request_malformed(name: str, pairing: str, edit: Edit) -> None:
    c = presented(pairing, edit)
    assert pairings_of(offer_of(c)) == Refusal("mpp/request-malformed")
    assert bound(pairing, c) == Refusal("mpp/request-malformed")


def test_an_absent_carrier_is_the_members_own_refusal() -> None:
    solana = presented("mpp/charge/solana", without("externalId"))
    assert bound("mpp/charge/solana", solana) == Refusal("svm/carrier-mismatch")
    near = presented("mpp/charge/nearintents", without("externalId"))
    assert bound("mpp/charge/nearintents", near) == Refusal("near/memo-not-lcp")
    xrpl = presented("mpp/charge/xrpl", without_detail("invoiceId"))
    assert bound("mpp/charge/xrpl", xrpl) == Refusal("xrpl/carrier-mismatch")


# The codes pairings_of gives the same request: an MPP Stellar charge names stellar:pubnet or stellar:testnet, and its
# recipient is a Stellar account or its muxed form.
@pytest.mark.parametrize(
    "edit",
    [member("recipient", 7), member("recipient", "GBAD"), detail("network", "stellar:mars"), without_detail("network")],
    ids=["recipient 7", 'recipient "GBAD"', 'network "stellar:mars"', "no network"],
)
def test_stellar_reads_its_network_and_recipient(edit: Edit) -> None:
    c = presented("mpp/charge/stellar", edit)
    assert pairings_of(offer_of(c)) == Refusal("stellar/option-malformed")
    assert bound("mpp/charge/stellar", c) == Refusal("stellar/option-malformed")


@pytest.mark.parametrize(
    ("edit", "code"),
    [
        (detail("escrowContract", "0x12"), "mpp/escrow-malformed"),
        (without_detail("escrowContract"), "mpp/escrow-malformed"),
        (without_detail("chainId"), "mpp/chain-id-required"),
        (member("currency", "usdc"), "mpp/request-malformed"),
        (without("recipient"), "mpp/request-malformed"),
    ],
    ids=['escrowContract "0x12"', "no escrowContract", "no chainId", 'currency "usdc"', "no recipient"],
)
def test_session_evm_reads_the_escrow_the_chain_the_recipient_and_the_currency(edit: Edit, code: str) -> None:
    assert bound("mpp/session/evm", presented("mpp/session/evm", edit)) == Refusal(code)


# The codes pairings_of gives the same request: a Tempo session's sessionProtocol is absent, "v1" or "v2", and a v2
# session names its chainId and its escrowContract (draft-tempo-session-00: "When methodDetails.sessionProtocol is "v2",
# servers MUST include methodDetails.chainId and methodDetails.escrowContract in the challenge after applying
# defaults.").
@pytest.mark.parametrize(
    ("edit", "code"),
    [
        (detail("sessionProtocol", "v3"), "mpp/session-protocol"),
        (without_detail("chainId"), "mpp/chain-id-required"),
        (without_detail("escrowContract"), "mpp/chain-id-required"),
    ],
    ids=['sessionProtocol "v3"', "v2 without chainId", "v2 without escrowContract"],
)
def test_session_tempo_reads_the_protocol_version_and_the_chain(edit: Edit, code: str) -> None:
    assert details(request_of(presented("mpp/session/tempo")))["sessionProtocol"] == "v2"
    c = presented("mpp/session/tempo", edit)
    assert pairings_of(offer_of(c)) == Refusal(code)
    assert bound("mpp/session/tempo", c) == Refusal(code)
    assert channel_ref("mpp/session/tempo", c) == Refusal(code)


# The Gateway salt's preimage carries the request's recipient, which pairings_of requires to be a string. The payer's
# salt here is computed with the recipient read as "".
def test_the_gateway_reads_the_recipient_its_salt_carries() -> None:
    c = presented("mpp/charge/usdc/gateway", member("recipient", 5))
    p = c["payload"]
    intent = p["authorization"]["transfer"]["burnIntent"]
    request_hash = usdc_request_hash(c["challenge"]["request"])
    assert isinstance(request_hash, str)
    salt = usdc_gateway_salt(
        {
            "id": c["challenge"]["id"],
            "realm": c["challenge"]["realm"],
            "requestHash": request_hash,
            "sourceNetwork": p["sourceNetwork"],
            "destinationNetwork": p["destinationNetwork"],
            "sourceDepositor": c["source"],
            "sourceSigner": gateway_account(p["sourceNetwork"], intent["spec"]["sourceSigner"]),
            "recipient": "",
            "destinationRecipient": gateway_account(p["destinationNetwork"], intent["spec"]["destinationRecipient"]),
            "amount": intent["spec"]["value"],
            "maxFee": intent["maxFee"],
        }
    )
    assert isinstance(salt, str)
    intent["spec"]["salt"] = salt
    assert pairings_of(offer_of(c)) == Refusal("mpp/request-malformed")
    assert bound("mpp/charge/usdc/gateway", c) == Refusal("mpp/request-malformed")


def test_the_hedera_escrow_and_the_solana_channel_program() -> None:
    hedera = presented("mpp/session/hedera", without_detail("escrowContract"))
    assert bound("mpp/session/hedera", hedera) == Refusal("mpp/request-malformed")
    solana = presented("mpp/session/solana", detail("channelProgram", "program"))
    assert bound("mpp/session/solana", solana) == Refusal("svm/input-malformed")


def test_the_session_openings_read_no_other_request_member() -> None:
    named = detail("channelId", "0x" + "11" * 32)
    assert bound("mpp/session/hedera", presented("mpp/session/hedera", named)) == expected_h("mpp/session/hedera")
    assert bound("mpp/session/hedera", presented("mpp/session/hedera", member("currency", "usdc"))) == expected_h(
        "mpp/session/hedera"
    )
    assert bound("mpp/session/solana", presented("mpp/session/solana", member("currency", "usdc"))) == expected_h(
        "mpp/session/solana"
    )
    assert bound("mpp/session/xrpl", presented("mpp/session/xrpl", without_detail("network"))) == expected_h(
        "mpp/session/xrpl"
    )


def test_subscription_tempo_reads_only_the_chain() -> None:
    unread = both(
        member("amount", "abc"),
        member("periodUnit", "month"),
        member("currency", "pathUSD"),
        member("recipient", "nobody"),
        no_expires,
    )
    pairing = "mpp/subscription/tempo"
    assert bound(pairing, presented(pairing, unread)) == expected_h(pairing)
    assert channel_ref(pairing, presented(pairing, unread)) == channel_ref(pairing, presented(pairing))
    assert channel_ref(pairing, presented(pairing, without_detail("chainId"))) == Refusal("mpp/chain-id-required")
