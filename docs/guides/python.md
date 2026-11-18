---
title: Python
description: The Python buyer gate, integraledger-terms — the same rules and the same vectors as the TypeScript gate, with Python names and dataclass results.
---

`integraledger-terms` is the buyer gate in Python. It is a second implementation of the same rules, not a wrapper: it
carries its own bindings, one module-level constant per pairing, and runs the same shared vectors as the TypeScript
gate, so for the same inputs the two build the same payments.

This guide is for a developer who pays from Python. By its end you know where the Python gate differs from the
TypeScript one, how to write a signer, and which call runs each flow.

```sh
pip install integraledger-terms==0.5.0
```

Python `>=3.11`. It depends on `httpx` (`>=0.28.1,<0.29`) and `cryptography` (`==50.0.2`, an exact pin: install it in an
environment that can take that version), and is fully typed.

## Differences from the TypeScript gate

| | TypeScript | Python |
| --- | --- | --- |
| Binding | an export of `@integraledger/lcp`, such as `exactEip3009` | a constant of `integraledger_terms`, such as `X402_EXACT_EIP155_EIP3009` |
| HTTP client | `fetch`, WHATWG's call shape | an `httpx.AsyncClient` |
| Result | an object, or `{ decline: { code, detail }, moved? }` | a dataclass (`Transacted`, `Confirmed`, `Finished`, …), or `Declined(code, detail, moved)` |
| ATR bytes | `bytes: Uint8Array` | `atr_bytes: bytes` |
| `transact`'s options | `{ approver, resourceRequest, inputs, ceilings, legalContext, agreementSigner, approved, signal, chosen }` | keyword arguments `approver=`, `resource_request=`, `inputs=`, `ceilings=`, `legal_context=`, `agreement_signer=`, `approved=`, `signal=`, `chosen=` |
| The approver | `(toSign: ToSign) => boolean \| Promise<boolean>`; approves with `true` | `Callable[[ToSign], bool \| Awaitable[bool]]`; approves with `True` |
| The buyer's request | `ResourceRequest`, the protocol package's `HttpRequest` (`body` a `Uint8Array`) or `ToolCall` | `ResourceRequest`, the `TypedDict`s `HttpRequest` (`body` as `bytes`) and `ToolCall`, with the same member names |
| `ToSign`, `Summary`, `ToReturn`, `AgreementChallenges` | objects, members in camel case (`limitPerPeriod`, `closableBy`, `legalContext`, `agreementChallenges`) | frozen dataclasses, members in snake case (`limit_per_period`, `closable_by`, `legal_context`, `agreement_challenges`) |
| A later step of a payment signed in steps | `{ next, summary, h }` | `Next(next, summary, h)` |
| Ending the agreement exchange | `signal`, an `AbortSignal` | `signal=`, an `asyncio.Event` that you set |
| The agreement payment to approve | `{ approve, bytes, h }` | `ToApprove(approve, atr_bytes, h)` |
| Byte strings in a signing request | `Uint8Array`, as built | `0x` and lower-case hex |
| Channel functions | `openChannel`, `within`, `recordCharge` | `open_channel`, `within`, `record_charge` |

The HTTP clients also differ on some hosts that both gates accept in an `https` link. `httpx` refuses an `xn--` label
that is not valid Punycode, such as `xn--zz`, and a label IDNA 2008 does not allow, such as `xn--a` or `xn--ls8h`. In
the Python gate, an ATR link on such a host is declined `atr-unfetchable`, and an agreement URL on one is declined
`agreement-failed`; nothing is fetched. The TypeScript gate passes such a link to its `fetch`.

Everything else is the same: the order of the steps and the checks, the parse of the ATR, the bounds of the fetch, the
identity-only content coding, the summaries, the ceilings and their paces, the decline codes, the agreement exchange and
its timings, the channel hold's members. Both are held to the profile
[`buyer-gate.md`](https://github.com/IntegraLedger/integra-agentic-terms/blob/main/agentic-terms/profiles/buyer-gate.md)
and its vectors.

## A signer

Any object with an `account` string (CAIP-10) and an `async def sign(self, request)` method is a signer. It receives
the request as a `dict`, with every byte string as `0x` and lower-case hex, and returns its answer as JSON-ready
values:

```python no-run
from collections.abc import Mapping
from typing import Any

from eth_account import Account
from eth_account.messages import encode_typed_data


class Wallet:
    """Signs EIP-712 requests with one key, and refuses every other kind."""

    def __init__(self, key: str, account: str) -> None:
        self._key = key
        self.account = account

    async def sign(self, request: Mapping[str, Any]) -> str:
        if request["kind"] != "eip712":
            raise ValueError(f"this wallet does not sign {request['kind']}")
        signed = Account.sign_message(encode_typed_data(full_message=dict(request["typedData"])), self._key)
        return "0x" + bytes(signed.signature).hex()
```

A signer that raises is a `Declined("signer-failed", …)`.

## The flows

- **One call:** `await transact(doc, binding, signer, client, approver=…, resource_request=…, inputs=…)`. Each signing
  is asked of `approver` first. Where the pairing needs an agreement payment, the call returns `ToApprove` and signs
  nothing; once your agent approves `result.approve`, call again with `approved=result.approve`. Where the seller offers
  the agreement alone, it returns `ToReturn` once the agreement is paid. Where the agreement URL offers only MPP
  agreement challenges, it returns `AgreementChallenges` and signs nothing. Given `chosen=confirmed.chosen`, it builds
  the exact request `confirm` returned.
- **Two calls:** `await confirm(doc, binding, account, client, resource_request=…, inputs=…)`, which returns the request
  with its `summary` and calls no approver, then your signer, then `finish(atr_bytes, chosen, signature, binding)`,
  which returns `Finished` with the payment to send, or, for a payment signed in steps, `Next(next, summary, h)` for
  the later step to show and sign.
- **Later:** `check(atr_bytes, presented, binding, landed=…, act=…)`, `act` being `"agreement"` for an agreement
  payment. The caller passes as `landed` only the receipt its own
  reader read for the payment, as `finish` or `transact` returned it, never a value another party sent.
- **Agreement:** `await agree(atr_bytes, url, signer, client, chosen=…)` returns `ToApprove` (or `AgreementChallenges`,
  where the agreement URL offers only MPP agreement challenges), signing nothing; once your
  agent approves it, `await agree(atr_bytes, url, signer, client, approved=…, chosen=…)` holds it to its summary and
  its pairing's ceiling (`ceilings=` raises it), pays it and returns `Agreed`.
- **Channels:** `open_channel(atr_bytes, opened, binding, landed=…)`, `await within(doc, hold, binding, signer)`,
  `record_charge(hold, charged)`. The caller passes as `landed` only the receipt its own reader read for the opening,
  as `transact` returned it, never a value another party sent.

The [Python README](https://github.com/IntegraLedger/integra-agentic-terms/tree/main/agentic-terms-py#readme) runs each
of them against the shared vectors, and the [Python reference](../reference/python.md) lists every export.

## Running the tests

From a checkout, after `pnpm install` (the tests read the shared vectors from the installed `@integraledger/lcp`):

```sh
cd agentic-terms-py
uv run --locked --python 3.11 pytest -q
uv run --locked --python 3.14 pytest -q
uv run --locked --python 3.14 mypy --strict src tests
```

## Versions and upgrading

`integraledger-terms` is at 0.x: a minor release may change the public API. Pin the exact version, as the install line
above does. 0.5.x builds and reads the forms of `@integraledger/lcp` 0.6.0 and needs Python `>=3.11`.

From 0.4.x, `confirm` takes `resource_request=` (required) and `inputs=` as keywords, and `transact` requires
`approver=` and `resource_request=`: a 0.4.x call raises `TypeError`. `transact` may also return `ToReturn` and
`AgreementChallenges`, `Next` carries `summary`, every payment `transact`, `confirm` or `finish` builds is held to its
pairing's ceiling, 600 seconds unless `ceilings` raises it, and `DeclineCode` has eight new codes. The package's
[CHANGELOG](https://github.com/IntegraLedger/integra-agentic-terms/blob/main/agentic-terms-py/CHANGELOG.md) lists every
change.
