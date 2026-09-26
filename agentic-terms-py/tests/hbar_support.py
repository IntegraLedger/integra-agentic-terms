"""What the Hedera, NEAR, Tron and TON rows share, as the TypeScript gate's rails tests do: the document with an http
link, the document advertising payment-identifier, and B10 and B16."""

import copy
import re
from typing import Any

from integraledger_terms import Declined, Transacted, confirm, transact

from breadth import ABC, Pairing, Recording, link_calls, offered, run
from support import serving

EVM_ACCOUNT = "eip155:84532:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
REF = re.compile(r"[A-Za-z0-9_-]{32}")


def http_doc(doc: Any) -> Any:
    """The document with its legal context's link as http://."""
    out = copy.deepcopy(doc)
    info = out["extensions"]["legalContext"]["info"]
    info["legalContextUrl"] = str(info["legalContextUrl"]).replace("https://", "http://")
    return out


def with_identifier(doc: Any) -> Any:
    """The document also advertising the payment-identifier extension."""
    out = copy.deepcopy(doc)
    out["extensions"] = {**out["extensions"], "payment-identifier": {"info": {}, "schema": {}}}
    return out


def b10(p: Pairing) -> None:
    """B10: an http link is offer-unreadable, x402/link-not-https, before any fetch."""
    out, calls = link_calls(p, p.account, http_doc(p.doc))
    assert isinstance(out, Declined) and out.code == "offer-unreadable", out
    assert out.detail == "x402/link-not-https"
    assert calls == 0


def b16(p: Pairing, others: list[str]) -> None:
    """B16: an account of another namespace, and one on another network, have no payable option; nothing is
    fetched."""
    for account in others:
        out, calls = link_calls(p, account)
        assert isinstance(out, Declined) and out.code == "no-payable-option", (account, out)
        assert calls == 0


def identifier_row(p: Pairing) -> None:
    """B6 · payment identifier: transact appends id = ref to the echoed extension where the challenge advertises it."""
    signer = Recording(p.account, p.answer)
    out = run(lambda c: transact(with_identifier(p.doc), offered(p.binding), signer, c, inputs=p.inputs), serving(ABC))
    assert isinstance(out, Transacted) and out.signed is not None, out
    assert REF.fullmatch(out.signed["extensions"]["payment-identifier"]["info"]["id"])


def inputs_row(p: Pairing, inputs: dict[str, Any], detail: str) -> None:
    """A missing or malformed input is no-payable-option with the pairing's input-missing, before any fetch."""
    link = serving(ABC)
    out = run(lambda c: confirm(p.doc, p.binding, p.account, c, inputs), link)
    assert out == Declined("no-payable-option", detail), out
    assert link.calls == 0
