---
title: Python
description: The Python buyer gate, integraledger-terms — the same rules and the same vectors as the TypeScript gate, with Python names and dataclass results.
---

`integraledger-terms` is the buyer gate in Python. It is a second implementation of the same rules, not a wrapper: it
carries its own bindings, one module-level constant per pairing, and runs the same shared vectors as the TypeScript
gate, so for the same inputs the two build the same payments.

```sh
pip install integraledger-terms
```

Python `>=3.11`. It depends on `httpx` and `cryptography`, and is fully typed.

## Differences from the TypeScript gate

| | TypeScript | Python |
| --- | --- | --- |
| Binding | an export of `@integraledger/lcp`, such as `exactEip3009` | a constant of `integraledger_terms`, such as `X402_EXACT_EIP155_EIP3009` |
| HTTP client | `fetch`, WHATWG's call shape | an `httpx.AsyncClient` |
| Result | an object, or `{ decline: { code, detail }, moved? }` | a dataclass (`Transacted`, `Confirmed`, `Finished`, …), or `Declined(code, detail, moved)` |
| ATR bytes | `bytes: Uint8Array` | `atr_bytes: bytes` |
| `transact`'s options | `{ inputs, agreementSigner, approved, signal }` | keyword arguments `inputs=`, `agreement_signer=`, `approved=`, `signal=` |
| Ending the agreement exchange | `signal`, an `AbortSignal` | `signal=`, an `asyncio.Event` that you set |
| The agreement payment to approve | `{ approve, bytes, h }` | `ToApprove(approve, atr_bytes, h)` |
| Byte strings in a signing request | `Uint8Array`, as built | `0x` and lower-case hex |
| Channel functions | `openChannel`, `within`, `recordCharge` | `open_channel`, `within`, `record_charge` |

Everything else is the same: the order of the steps, the bounds of the fetch, the identity-only content coding, the
twelve decline codes, the agreement
exchange and its timings, the channel hold's members.

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

- **One call:** `await transact(doc, binding, signer, client, inputs=…, agreement_signer=…)`. Where the pairing needs
  an agreement payment, the call returns `ToApprove` and signs nothing; once your agent approves `result.approve`, call
  again with `approved=result.approve`.
- **Two calls:** `await confirm(doc, binding, account, client, inputs)`, then your signer, then
  `finish(atr_bytes, chosen, signature, binding)`.
- **Later:** `check(atr_bytes, presented, binding)`.
- **Agreement:** `await agree(atr_bytes, url, signer, client)` returns `ToApprove`, signing nothing; once your agent
  approves it, `await agree(atr_bytes, url, signer, client, approved=…)` pays it and returns `Agreed`.
- **Channels:** `open_channel(atr_bytes, opened, binding)`, `await within(doc, hold, binding, signer)`,
  `record_charge(hold, charged)`.

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
