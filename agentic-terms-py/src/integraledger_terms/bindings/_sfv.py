"""The RFC 9651 subset the two TAP signature fields need: a Dictionary whose members are Items or Inner Lists, with
Integer, String, Token, Boolean and Byte Sequence items and parameters. A Decimal, Date or Display String fails. A
repeated key overwrites the earlier value in its first place."""

from dataclasses import dataclass
from typing import Literal

BareType = Literal["integer", "string", "token", "boolean", "bytes"]


@dataclass(frozen=True, slots=True)
class Bare:
    t: BareType
    v: object


Params = dict[str, Bare]


@dataclass(frozen=True, slots=True)
class Item:
    item: Bare
    params: Params


@dataclass(frozen=True, slots=True)
class InnerList:
    list: list[Item]
    params: Params


Member = Item | InnerList


class _TooLarge:
    """The dictionary has more members, or an inner list more items, than the bounds allow."""


TOO_LARGE = _TooLarge()

_LC_ALPHA = frozenset("abcdefghijklmnopqrstuvwxyz")
_ALPHA = _LC_ALPHA | frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
_DIGIT = frozenset("0123456789")
_KEY = _LC_ALPHA | _DIGIT | frozenset("_-.*")
_TOKEN = _ALPHA | _DIGIT | frozenset(":/!#$%&'*+-.^_`|~")
_BASE64 = _ALPHA | _DIGIT | frozenset("+/=")


class _Parser:
    def __init__(self, text: str, max_members: int, max_items: int) -> None:
        self.s = text
        self.i = 0
        self.n = len(text)
        self.max_members = max_members
        self.max_items = max_items

    def at(self, index: int) -> str:
        return self.s[index] if 0 <= index < self.n else ""

    def sp(self) -> None:
        while self.i < self.n and self.s[self.i] == " ":
            self.i += 1

    def ows(self) -> None:
        while self.i < self.n and self.s[self.i] in " \t":
            self.i += 1

    def key(self) -> str | None:
        first = self.at(self.i)
        if first == "" or not (first in _LC_ALPHA or first == "*"):
            return None
        start = self.i
        self.i += 1
        while self.i < self.n and self.s[self.i] in _KEY:
            self.i += 1
        return self.s[start : self.i]

    def bare(self) -> Bare | None:
        c = self.at(self.i)
        if c == "":
            return None
        if c == "-" or c in _DIGIT:
            start = self.i
            if c == "-":
                self.i += 1
            digits_at = self.i
            while self.i < self.n and self.s[self.i] in _DIGIT:
                self.i += 1
            count = self.i - digits_at
            if count == 0 or count > 15 or self.at(self.i) == ".":
                return None
            return Bare("integer", int(self.s[start : self.i]))
        if c == '"':
            self.i += 1
            value = []
            while self.i < self.n:
                d = self.s[self.i]
                self.i += 1
                if d == "\\":
                    e = self.at(self.i)
                    self.i += 1
                    if e not in ('"', "\\"):
                        return None
                    value.append(e)
                elif d == '"':
                    return Bare("string", "".join(value))
                else:
                    if ord(d) < 0x20 or ord(d) > 0x7E:
                        return None
                    value.append(d)
            return None
        if c in _ALPHA or c == "*":
            start = self.i
            self.i += 1
            while self.i < self.n and self.s[self.i] in _TOKEN:
                self.i += 1
            return Bare("token", self.s[start : self.i])
        if c == ":":
            self.i += 1
            start = self.i
            while self.i < self.n and self.s[self.i] in _BASE64:
                self.i += 1
            if self.at(self.i) != ":":
                return None
            value_bytes = self.s[start : self.i]
            self.i += 1
            return Bare("bytes", value_bytes)
        if c == "?":
            b = self.at(self.i + 1)
            if b not in ("0", "1"):
                return None
            self.i += 2
            return Bare("boolean", b == "1")
        return None

    def params(self) -> Params | None:
        p: Params = {}
        while self.at(self.i) == ";":
            self.i += 1
            self.sp()
            k = self.key()
            if k is None:
                return None
            v = Bare("boolean", True)
            if self.at(self.i) == "=":
                self.i += 1
                given = self.bare()
                if given is None:
                    return None
                v = given
            p[k] = v
        return p

    def item(self) -> Item | None:
        b = self.bare()
        if b is None:
            return None
        p = self.params()
        return None if p is None else Item(b, p)

    def inner_list(self) -> InnerList | None | _TooLarge:
        self.i += 1
        items: list[Item] = []
        while self.i < self.n:
            self.sp()
            if self.at(self.i) == ")":
                self.i += 1
                p = self.params()
                return None if p is None else InnerList(items, p)
            if len(items) >= self.max_items:
                return TOO_LARGE
            it = self.item()
            if it is None:
                return None
            items.append(it)
            if self.at(self.i) not in (" ", ")"):
                return None
        return None

    def dictionary(self) -> dict[str, Member] | None | _TooLarge:
        out: dict[str, Member] = {}
        members = 0
        self.sp()
        while self.i < self.n:
            if members >= self.max_members:
                return TOO_LARGE
            members += 1
            k = self.key()
            if k is None:
                return None
            m: Member | None | _TooLarge
            if self.at(self.i) == "=":
                self.i += 1
                m = self.inner_list() if self.at(self.i) == "(" else self.item()
            else:
                p = self.params()
                m = None if p is None else Item(Bare("boolean", True), p)
            if m is None or isinstance(m, _TooLarge):
                return m
            out[k] = m
            self.ows()
            if self.i >= self.n:
                return out
            if self.at(self.i) != ",":
                return None
            self.i += 1
            self.ows()
            if self.i >= self.n:
                return None
        return out


def parse_dictionary(text: str, max_members: int, max_items: int) -> dict[str, Member] | None | _TooLarge:
    """The Dictionary the text holds; None when it does not parse; TOO_LARGE past max_members members or max_items
    items in an inner list."""
    return _Parser(text, max_members, max_items).dictionary()
