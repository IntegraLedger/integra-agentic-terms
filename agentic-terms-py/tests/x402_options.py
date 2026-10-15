"""The x402 bindings, the x402 options @integraledger/lcp's vector files hold, and a document that offers options."""

from collections.abc import Callable, Iterator
from typing import Any

import integraledger_terms
from integraledger_terms import Refusal

from support import VECTORS, load

BINDINGS: dict[str, Any] = {
    binding.id: binding
    for binding in (getattr(integraledger_terms, name) for name in integraledger_terms.__all__)
    if isinstance(getattr(binding, "id", None), str) and binding.id.startswith("x402/")
}
FILES = sorted(path.name for path in VECTORS.glob("x402-*.json")) + ["buyer.json"]


def options_in(value: Any) -> Iterator[dict[str, Any]]:
    """Every object in a vector file that names a scheme and a network, as an x402 option does."""
    if isinstance(value, list):
        for item in value:
            yield from options_in(item)
    elif isinstance(value, dict):
        if isinstance(value.get("scheme"), str) and isinstance(value.get("network"), str):
            yield value
        for item in value.values():
            yield from options_in(item)


OPTIONS = [option for name in FILES for option in options_in(load(name))]


def offering(*options: Any) -> dict[str, Any]:
    """A document offering the options, with a legal context."""
    info = {"type": "sha256", "value": "0x" + "00" * 32, "legalContextUrl": "https://pairing.invalid/"}
    return {
        "x402Version": 2,
        "resource": {"url": "https://pairing.invalid/"},
        "accepts": list(options),
        "extensions": {"legalContext": {"info": info}},
    }


def first_offered(pairing: str, change: Callable[[dict[str, Any]], dict[str, Any]]) -> dict[str, Any] | None:
    """The first vector option, changed, that the pairing's read offers."""
    read = BINDINGS[pairing].read
    changed = (change(o) for o in OPTIONS)
    return next((o for o in changed if not isinstance(read(offering(o)), Refusal)), None)
