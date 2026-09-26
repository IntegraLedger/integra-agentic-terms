"""A bounded CBOR reader (RFC 8949) that keeps each item's byte span. Definite and indefinite lengths and tags are
read; nesting is at most 64 deep. Anything malformed raises CborError."""

from dataclasses import dataclass, field
from typing import Any

MAX_DEPTH = 64


class CborError(Exception):
    pass


@dataclass(slots=True)
class Item:
    """One data item: its kind, its span [start, end) in the bytes, and its content. kind is uint, nint, bytes, text,
    array, map, tag, simple or float; value holds a uint's, bytes', text's, simple's value or a tag number; items an
    array's items, a map's entries as pairs, or a tag's one item."""

    kind: str
    start: int
    end: int = 0
    value: Any = None
    items: list[Any] = field(default_factory=list)


class SpanReader:
    def __init__(self, b: bytes) -> None:
        self.b = b
        self.at = 0

    def _byte(self) -> int:
        if self.at >= len(self.b):
            raise CborError("short")
        self.at += 1
        return self.b[self.at - 1]

    def _take(self, n: int) -> bytes:
        if n > len(self.b) - self.at:
            raise CborError("short")
        out = self.b[self.at : self.at + n]
        self.at += n
        return out

    def _argument(self, info: int) -> int:
        if info < 24:
            return info
        if info > 27:
            raise CborError("reserved")
        return int.from_bytes(self._take(1 << (info - 24)), "big")

    def _is_break(self) -> bool:
        """Consumes a break byte when one is next."""
        if self.at >= len(self.b):
            raise CborError("short")
        if self.b[self.at] != 0xFF:
            return False
        self.at += 1
        return True

    @staticmethod
    def _text(data: bytes) -> str:
        try:
            return data.decode("utf-8-sig")
        except UnicodeDecodeError as e:
            raise CborError("text") from e

    def item(self, depth: int) -> Item:
        if depth > MAX_DEPTH:
            raise CborError("too deep")
        start = self.at
        head = self._byte()
        major, info = head >> 5, head & 0x1F
        if info == 31:
            return self._indefinite(major, start, depth)
        arg = self._argument(info)
        it = Item("", start)
        if major == 0:
            it.kind, it.value = "uint", arg
        elif major == 1:
            it.kind = "nint"
        elif major == 2:
            it.kind, it.value = "bytes", self._take(arg)
        elif major == 3:
            it.kind, it.value = "text", self._text(self._take(arg))
        elif major == 4:
            it.kind = "array"
            i = 0
            while i < arg:
                it.items.append(self.item(depth + 1))
                i += 1
        elif major == 5:
            it.kind = "map"
            i = 0
            while i < arg:
                k = self.item(depth + 1)
                it.items.append((k, self.item(depth + 1)))
                i += 1
        elif major == 6:
            it.kind, it.value = "tag", arg
            it.items.append(self.item(depth + 1))
        elif info >= 25:
            it.kind = "float"
        else:
            if info == 24 and arg < 32:
                raise CborError("simple value")
            it.kind, it.value = "simple", arg
        it.end = self.at
        return it

    def _indefinite(self, major: int, start: int, depth: int) -> Item:
        it = Item("", start)
        if major in (2, 3):
            chunks = bytearray()
            while not self._is_break():
                head = self._byte()
                if head >> 5 != major or head & 0x1F == 31:
                    raise CborError("chunk")
                chunks += self._take(self._argument(head & 0x1F))
            it.kind, it.value = ("bytes", bytes(chunks)) if major == 2 else ("text", self._text(bytes(chunks)))
        elif major == 4:
            it.kind = "array"
            while not self._is_break():
                it.items.append(self.item(depth + 1))
        elif major == 5:
            it.kind = "map"
            while not self._is_break():
                k = self.item(depth + 1)
                it.items.append((k, self.item(depth + 1)))
        else:
            raise CborError("indefinite")
        it.end = self.at
        return it
