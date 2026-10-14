"""Byte helpers the rail bindings share: padded standard base64 in its canonical form with a size bound checked
before decoding, decimal strings below a limit, and the JSON a rail wire form may carry."""

import re
from typing import Any, Literal

from ._codec import b64_decode
from ._jose import UNPARSED, js_length
from ._jose import parse_json as parse_json_text

U64_LIMIT = 1 << 64

_DECIMAL = re.compile(r"[0-9]{1,78}")


def base64_bytes(text: object, max_bytes: int) -> bytes | Literal["too-large", "malformed"]:
    """The bytes of padded standard base64 as b64_decode reads it (the canonical form only), "too-large" when they
    would exceed max_bytes, or "malformed". The length is checked before anything is decoded, in UTF-16 code units
    as String.prototype.length counts it."""
    if not isinstance(text, str) or js_length(text) % 4 != 0:
        return "malformed"
    pad = 2 if text.endswith("==") else 1 if text.endswith("=") else 0
    if js_length(text) // 4 * 3 - pad > max_bytes:
        return "too-large"
    data = b64_decode(text)
    return "malformed" if data is None else data


def decimal_below(value: object, limit: int) -> int | None:
    """A decimal string of at most 78 digits below limit, or None."""
    if not isinstance(value, str) or _DECIMAL.fullmatch(value) is None:
        return None
    n = int(value)
    return n if n < limit else None



def parse_json(data: bytes) -> Any:
    """Strict UTF-8 JSON text as JSON.parse reads it (no NaN or Infinity), nested at most 64 levels deep; raises
    ValueError for anything else."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError("not JSON") from e
    value = parse_json_text(text)
    if value is UNPARSED:
        raise ValueError("not JSON")
    return value
