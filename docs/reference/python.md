---
title: Python API
description: Every export of integraledger_terms, with its signature and what it returns.
---

Everything on this page is exported from `integraledger_terms`. Python `>=3.11`. No function raises for a protocol
outcome: each returns its result or a `Declined`.

## Functions

| Function | Signature | Returns |
| --- | --- | --- |
| `transact` | `async transact(doc, binding, signer, fetch, *, inputs=None, agreement_signer=None, approved=None, signal=None)` | `Transacted \| ToApprove \| Declined` |
| `confirm` | `async confirm(doc, binding, account, fetch, inputs=None)` | `Confirmed \| Declined` |
| `finish` | `finish(atr_bytes, chosen, signature, binding)` | `Finished \| Next \| Declined` |
| `check` | `check(atr_bytes, presented, binding)` | `Checked \| Declined` |
| `agree` | `async agree(atr_bytes, url, signer, fetch, *, approved=None, inputs=None, signal=None)` | `ToApprove \| Agreed \| Declined` |
| `open_channel` | `open_channel(atr_bytes, opened, binding, landed=None)` | `ChannelHold \| Declined` |
| `within` | `async within(doc, hold, binding, signer, refund=None, inputs=None)` | `Within \| Declined` |
| `record_charge` | `record_charge(hold, charged_cumulative_amount)` | `ChannelHold \| Declined` |
| `atr_hash` | `atr_hash(data: bytes)` | `AtrHash`: SHA-256 as `0x` and 64 lower-case hex digits |
| `hash_equals` | `hash_equals(a: str, b: str)` | `bool`: the two hashes as 32 decoded bytes, in either case; `False` when either is malformed |

`fetch` is an `httpx.AsyncClient`. The gate asks it for one `GET` of the link with `Accept-Encoding: identity`, no
redirect, and a 10-second deadline over headers and body. It reads the body as sent, with `aiter_raw`, and stops at
1 MiB. A `200` whose `Content-Encoding` names any coding is declined `atr-unfetchable` with its body unread: the gate
decompresses nothing, whatever the client would decode. The agreement URL is asked the same way, and its receipt read
as sent up to 64 KiB.

Each function does what its TypeScript namesake does; the [TypeScript reference](./typescript.md) describes each in
full. `approved` is the `AgreementPayment` a previous call returned in `ToApprove.approve`, carried back unchanged.

`signal` is an `asyncio.Event`: setting it ends the agreement exchange as aborting the `AbortSignal` does in
TypeScript. Before the agreement payment is sent, the call declines `agreement-failed` and nothing was signed or sent;
after, it declines `agreement-pending` with the payment as `moved`. Cancelling the task instead raises
`asyncio.CancelledError`, as asyncio does, and a payment already sent is then not returned; the signal keeps it.

## Results

| Dataclass | Fields |
| --- | --- |
| `Transacted` | `signed: dict \| None`, `atr_bytes: bytes`, `h: AtrHash`, `agreement: AgreementReceipt \| None`, `landed: Any` |
| `Confirmed` | `chosen: Chosen`, `request: dict \| None`, `atr_bytes: bytes`, `h: AtrHash` |
| `Finished` | `signed: dict`, `h: AtrHash`, `landed: Any` |
| `Next` | `next: dict`, `h: AtrHash` |
| `Checked` | `h: AtrHash` |
| `ToApprove` | `approve: AgreementPayment`, `atr_bytes: bytes`, `h: AtrHash` |
| `AgreementPayment` | `url: str`, `option: dict`, `required: dict`: the agreement payment to approve. `option` is the x402 option paid, with its `amount`, `asset`, `payTo` and `network`; `required` is the agreement URL's payment request as served. |
| `Agreed` | `receipt: AgreementReceipt` |
| `AgreementReceipt` | `atr_hash: AtrHash`, `agreed: Literal[True]`, `network: str`, `transaction: str` |
| `Within` | `signed: dict`, `hold: ChannelHold` |
| `Chosen` | `pairing: str`, `choice: dict`, `ref: str`, `agreement: str \| None`: the agreement URL, where the pairing needs one |
| `Declined` | `code: DeclineCode`, `detail: str`, `moved: Moved \| None` |

`ChannelHold` is a `dict` with the members `pairing`, `network`, `channel`, `h`, `atr`, `opening`, `charged` and
`signedMax`, as in TypeScript. `Moved` holds `signed`, `atr_bytes` and `h`.

## Protocols and types

| Export | What it is |
| --- | --- |
| `Signer` | A protocol: an `account` property (CAIP-10) and `async def sign(self, request: Json) -> Signature`. |
| `Binding` | A protocol: `id`, `public_proof`, `read(doc)`, `build(choice, h)`, `bound(presented)`. |
| `Advertised` | What a binding's `read` gives the gate: `h`, `link`, `offer`, `agreement`. |
| `Unsigned`, `Step`, `Refusal`, `BatchUnsigned`, `ChannelRef` | The values a binding and the gate exchange, for code that implements a binding. |
| `DeclineCode` | A `Literal` of the twelve codes in the [declines reference](./declines.md). |
| `AtrHash` | `str`. |
| `Json`, `Inputs` | `Mapping[str, Any]`. |
| `Signature` | `Any`: the signer's answer. |
| `MAX_ATR_BYTES` | `1048576`. |

## Bindings

One constant per pairing, named after the pairing's id: upper case, with `/` and `-` as `_`. For example
`x402/exact/eip155/eip3009` is `X402_EXACT_EIP155_EIP3009`, and `mpp/charge/usdc/solana` is `MPP_CHARGE_USDC_SOLANA`.
The [pairings reference](./pairings.md) lists every one.
