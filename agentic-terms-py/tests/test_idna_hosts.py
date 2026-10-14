"""Hosts the https-link rule accepts that httpx refuses. httpx passes each host through IDNA 2008 (the idna package,
RFC 5891) as it builds a request, and refuses an xn-- label whose Punycode (RFC 3492) does not decode, such as xn--zz,
and one that decodes to a code point IDNA 2008 does not allow, such as xn--a (U+0080, a control) and xn--ls8h (U+1F4A9,
a symbol): RFC 5892 derives every code point outside its letter, mark and digit categories as DISALLOWED. The Python
gate declines an ATR link on such a host atr-unfetchable and an agreement URL on one agreement-failed, with no request
sent and no signer call, as the Python guide and README state. xn--bcher-kva, the Punycode of "bücher", is the control:
IDNA 2008 allows its code points, and it is fetched."""

import unicodedata

import httpx
import idna
import pytest

from integraledger_terms import X402_EXACT_EIP155_EIP3009, Confirmed, Declined, agree, confirm
from integraledger_terms.bindings._lcp import is_agreement_url, is_https_link

from breadth import run
from support import A, ACCOUNT, HASH_A, EthAccountSigner, Link, document

REFUSED = ["xn--zz", "xn--a", "xn--ls8h"]
CONTROL = "xn--bcher-kva"


def atr_link(label: str) -> str:
    return f"https://{label}.example/{HASH_A}"


def agreement_url(label: str) -> str:
    return f"https://{label}.example/agreement/1"


def test_each_label_is_refused_by_idna_2008_and_the_control_is_not() -> None:
    with pytest.raises(UnicodeError):
        b"zz".decode("punycode")
    assert [unicodedata.category(b.decode("punycode")) for b in (b"a", b"ls8h")] == ["Cc", "So"]
    assert [ord(b.decode("punycode")) for b in (b"a", b"ls8h")] == [0x80, 0x1F4A9]
    for label in REFUSED:
        with pytest.raises(idna.IDNAError):
            idna.decode(f"{label}.example")
    assert idna.decode(f"{CONTROL}.example") == "bücher.example"
    for label in [*REFUSED, CONTROL]:
        assert is_https_link(atr_link(label)) and is_agreement_url(agreement_url(label))


@pytest.mark.parametrize("label", REFUSED)
def test_confirm_with_an_atr_link_on_such_a_host_is_atr_unfetchable_and_nothing_is_fetched(label: str) -> None:
    stub = Link(lambda _r: httpx.Response(200, content=A))
    out = run(lambda c: confirm(document(link=atr_link(label)), X402_EXACT_EIP155_EIP3009, ACCOUNT, c), stub)
    assert isinstance(out, Declined) and out.code == "atr-unfetchable", out
    assert stub.calls == 0


@pytest.mark.parametrize("label", REFUSED)
def test_agree_with_an_agreement_url_on_such_a_host_is_agreement_failed_and_nothing_is_fetched(label: str) -> None:
    stub = Link(lambda _r: httpx.Response(402))
    signer = EthAccountSigner()
    out = run(lambda c: agree(A, agreement_url(label), signer, c), stub)
    assert isinstance(out, Declined) and out.code == "agreement-failed" and out.moved is None, out
    assert (stub.calls, signer.calls) == (0, 0)


def test_the_control_host_is_fetched_by_confirm_and_by_agree() -> None:
    stub = Link(lambda _r: httpx.Response(200, content=A))
    assert isinstance(run(lambda c: confirm(document(link=atr_link(CONTROL)), X402_EXACT_EIP155_EIP3009, ACCOUNT, c), stub), Confirmed)
    assert stub.calls == 1
    agreement = Link(lambda _r: httpx.Response(402))
    run(lambda c: agree(A, agreement_url(CONTROL), EthAccountSigner(), c), agreement)
    assert agreement.calls == 1
