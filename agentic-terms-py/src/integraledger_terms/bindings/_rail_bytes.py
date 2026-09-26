"""Byte helpers the rail bindings share: strict padded base64 with a size bound checked before decoding, decimal
strings below a limit, and the JSON a rail wire form may carry."""

import base64
import binascii
import re
from typing import Any, Literal

from ._jose import UNPARSED
from ._jose import parse_json as parse_json_text

U64_LIMIT = 1 << 64

_BASE64 = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
_DECIMAL = re.compile(r"[0-9]{1,78}")


def base64_bytes(text: object, max_bytes: int) -> bytes | Literal["too-large", "malformed"]:
    """The bytes of a padded standard base64 string, "too-large" when they would exceed max_bytes, or "malformed".
    The length is checked before anything is decoded."""
    if not isinstance(text, str) or len(text) % 4 != 0:
        return "malformed"
    pad = 2 if text.endswith("==") else 1 if text.endswith("=") else 0
    if len(text) // 4 * 3 - pad > max_bytes:
        return "too-large"
    if _BASE64.fullmatch(text) is None:
        return "malformed"
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return "malformed"


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
