"""An agreement URL that is refused is link-not-https only when it is a string of at most 2048 characters that parses
as an absolute URL whose scheme is not https, and legal-context-malformed otherwise. Expected values are
core-vectors.json's links rows (refusedAs) and the lcp agreement-url test's values."""

from typing import Any

from support import load

from integraledger_terms.bindings._lcp import agreement_fault

LINKS: list[dict[str, Any]] = load("core-vectors.json")["links"]["rows"]
TOO_LONG_HTTP = "http://pay.seller.example/" + "a" * (2049 - len("http://pay.seller.example/"))
TOO_LONG = "https://pay.seller.example/" + "a" * (2049 - len("https://pay.seller.example/"))


def test_agreement_fault_on_the_refused_link_rows() -> None:
    refused = [r for r in LINKS if r["refusedAs"] != "accepted"]
    assert len(refused) == 17
    for row in refused:
        assert agreement_fault(row["link"]).fault == row["refusedAs"], row["name"]


def test_agreement_fault_other_schemes_and_malformed_values() -> None:
    for url in ("http://pay.seller.example/agreement", "HTTP://pay.seller.example/agreement", "ftp://pay.seller.example/a"):
        assert agreement_fault(url).fault == "link-not-https", url
    malformed: list[Any] = ["", "not a url", "https://", "https://exa mple.com/", "https://u@pay.seller.example/"]
    for url in [*malformed, TOO_LONG, TOO_LONG_HTTP, None, 7, ["http://pay.seller.example/"]]:
        assert agreement_fault(url).fault == "legal-context-malformed", str(url)[:40]
