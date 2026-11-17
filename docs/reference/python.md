---
title: Python API
description: Every export of integraledger_terms, with its signature and what it returns.
---

Everything on this page is exported from `integraledger_terms`. Python `>=3.11`. No function raises for a protocol
outcome: each returns its result or a `Declined`; nothing the seller serves and nothing the approver answers makes it
raise.

## Functions

| Function | Signature | Returns |
| --- | --- | --- |
| `transact` | `async transact(doc, binding, signer, fetch, *, approver, resource_request, inputs=None, ceilings=None, legal_context=None, agreement_signer=None, approved=None, signal=None, chosen=None)` | `Transacted \| ToApprove \| AgreementChallenges \| ToReturn \| Declined` |
| `confirm` | `async confirm(doc, binding, account, fetch, *, resource_request, inputs=None, ceilings=None)` | `Confirmed \| Declined` |
| `finish` | `finish(atr_bytes, chosen, signature, binding, *, ceilings=None)` | `Finished \| Next \| Declined` |
| `check` | `check(atr_bytes, presented, binding, landed=None, act="payment")` | `Checked \| Declined` |
| `agree` | `async agree(atr_bytes, url, signer, fetch, *, approved=None, inputs=None, signal=None, chosen=None)` | `ToApprove \| AgreementChallenges \| Agreed \| Declined` |
| `open_channel` | `open_channel(atr_bytes, opened, binding, landed=None)` | `ChannelHold \| Declined` |
| `within` | `async within(doc, hold, binding, signer, refund=None, inputs=None)` | `Within \| Declined` |
| `record_charge` | `record_charge(hold, charged_cumulative_amount)` | `ChannelHold \| Declined` |
| `atr_hash` | `atr_hash(data: bytes)` | `AtrHash`: SHA-256 as `0x` and 64 lower-case hex digits |
| `hash_equals` | `hash_equals(a: str, b: str)` | `bool`: the two hashes as 32 decoded bytes, in either case; `False` when either is malformed |
| `vi_json` | `vi_json(value)` | `str \| None`: the JSON text a Mastercard Verifiable Intent signer signs for the value, as TypeScript's `viJson` |

`fetch` is an `httpx.AsyncClient`. The gate asks it for one `GET` of the link with `Accept-Encoding: identity`, no
redirect, and a 10-second deadline over headers and body. It reads the body as sent, with `aiter_raw`, and stops at
1 MiB. A `200` whose `Content-Encoding` names any coding is declined `atr-unfetchable` with its body unread: the gate
decompresses nothing, whatever the client would decode. The agreement URL is asked the same way, and its receipt read
as sent up to 64 KiB.

Each function does what its TypeScript namesake does; the [TypeScript reference](./typescript.md) describes each in
full. `approved` is the `AgreementPayment` a previous call returned in `ToApprove.approve`, carried back unchanged.
`approver` is `Callable[[ToSign], bool | Awaitable[bool]]`, and approves only by answering `True`; `resource_request`
is an `HttpRequest` (`{"method", "target", "body", "headers"?}`, `body` as `bytes`) or a `ToolCall`
(`{"name", "arguments"?}`); `ceilings` maps a pairing id to an `int` of seconds, never a `bool`, or to `"no-end"`;
`chosen` is `Confirmed.chosen`, unchanged; `check`'s `act` is `"agreement"` for an agreement payment and `"payment"`,
the default, for any other.

`signal` is an `asyncio.Event`: setting it ends the agreement exchange as aborting the `AbortSignal` does in
TypeScript. Before the agreement payment is sent, the call declines `agreement-failed` and nothing was signed or sent;
after, it declines `agreement-pending` with the payment as `moved`. Cancelling the task instead raises
`asyncio.CancelledError`, as asyncio does, and a payment already sent is then not returned; the signal keeps it.

## Results

| Dataclass | Fields |
| --- | --- |
| `Transacted` | `signed: dict \| None`, `atr_bytes: bytes`, `h: AtrHash`, `agreement: AgreementReceipt \| None`, `landed: Any` |
| `ToReturn` | `agreement: AgreementReceipt \| None`, `legal_context: str`, `charge: str`, `atr_bytes: bytes`, `h: AtrHash`, `agreement_challenges: tuple[dict, ...] \| None`: the agreement paid, or its MPP agreement challenges for your own MPP client to pay, for a pairing paid after its agreement; exactly one of the two is not `None` |
| `AgreementChallenges` | `agreement_challenges: tuple[dict, ...]`, `atr_bytes: bytes`, `h: AtrHash`: the agreement resource's MPP agreement challenges, in the seller's order; nothing is signed |
| `Confirmed` | `chosen: Chosen`, `request: dict \| None`, `atr_bytes: bytes`, `h: AtrHash`, `summary: Summary \| None` |
| `Finished` | `signed: dict`, `h: AtrHash`, `landed: Any` |
| `Next` | `next: dict`, `summary: Summary`, `h: AtrHash` |
| `Checked` | `h: AtrHash` |
| `ToApprove` | `approve: AgreementPayment`, `atr_bytes: bytes`, `h: AtrHash` |
| `AgreementPayment` | `url: str`, `option: dict`, `required: dict`: the agreement payment to approve. `option` is the x402 option paid, with its `amount`, `asset`, `payTo` and `network`; `required` is the agreement URL's payment request as served. |
| `Agreed` | `receipt: AgreementReceipt` |
| `AgreementReceipt` | `atr_hash: AtrHash`, `agreed: Literal[True]`, `network: str`, `transaction: str` |
| `Within` | `signed: dict`, `hold: ChannelHold` |
| `Chosen` | `pairing: str`, `choice: dict`, `ref: str`, `agreement: str \| None`, `act`, `deadline: str \| None`: the agreement URL, where the pairing needs one, and the latest deadline handed to a wallet that picks its expiry |
| `ToSign` | `act: Literal["payment", "agreement"]`, `pairing: str`, `request: dict`, `summary: Summary`, `step: SigningStep` |
| `SigningStep` | `index: int`, `count: int` |
| `Summary` | `amount`, `maximum`, `payees: tuple[Payee, ...]`, `period`, `limit_per_period`, `end`, `operator`, `authorization_expiry`, `refund_expiry`, `deposit`, `closable_by`, `grant`, `asset: str`, `network: str \| None`, `validity: Validity`, `atr: bytes`; each other field a decimal `str` or `None` |
| `Payee` | `account: str`, `amount: str` |
| `Validity` | `not_before: str \| None`, `not_after: str \| None`, `unit: str` |
| `Declined` | `code: DeclineCode`, `detail: str`, `moved: Moved \| None` |
| `Moved` | `signed: Any`, `atr_bytes: bytes`, `h: AtrHash`: the payment the signer moved before a decline, to keep and present again |

`ChannelHold` is a `dict` with the members `pairing`, `network`, `channel`, `h`, `atr`, `opening`, `landed` (where
there is a read made for the opening), `charged` and `signedMax`, as in TypeScript.

## Protocols and types

| Export | What it is |
| --- | --- |
| `Signer` | A protocol: an `account` property (CAIP-10) and `async def sign(self, request: Json) -> Signature`. |
| `Binding` | A protocol: `id`, `read(doc)`, `build(choice, h, act=None)`, `bound(presented, given=None)`, `broadcaster(presented)`, carrying the protocol package's registry data for the pairing: its `coverage` (`"full"` or `"none"`) and, where its payment can be an agreement payment, its `agreement`. |
| `Approver` | `Callable[[ToSign], bool \| Awaitable[bool]]`. |
| `ResourceRequest`, `HttpRequest`, `ToolCall` | The buyer's own request, as `TypedDict`s. |
| `Ceilings` | `Mapping[str, int \| Literal["no-end"]]`. |
| `Advertised` | What a binding's `read` gives the gate: `h`, `link`, `offer`, `agreement`. |
| `Unsigned`, `Step`, `Refusal`, `BatchUnsigned`, `ChannelRef` | The values a binding and the gate exchange, for code that implements a binding. |
| `DeclineCode` | A `Literal` of the codes in the [declines reference](./declines.md). |
| `AtrHash` | `str`. |
| `Json`, `Inputs` | `Mapping[str, Any]`. |
| `Signature` | `Any`: the signer's answer. |
| `MAX_ATR_BYTES` | `1048576`. |
| `FLOOR_INPUTS` | `Mapping[str, tuple[str, ...]]`: each pairing whose rail has a served floor, to the names of its floor inputs in `inputs`. |

A binding's `broadcaster(presented)` names who puts the presented payment on its rail: `"payer"`, which sent it before
presenting it, so the seller reads a landed payment, or `"payee"`, the seller, or the facilitator or processor acting
for it, which sends or executes it. It answers only for a payment of a type and kind the pairing takes, within the
shape gate `bound` applies first, and gives any other payment the `Refusal` `bound` gives that fault. Where a payment
has a second fault that `bound` finds first, in H or the challenge, the two codes differ. A session's or batch
channel's `bound` reads the opening alone, so for any other action the reader is `channel_kind`: a payment it refuses
for its own content gets its refusal.

## Bindings

One constant per pairing, named after the pairing's id: upper case, with `/` and `-` as `_`. For example
`x402/exact/eip155/eip3009` is `X402_EXACT_EIP155_EIP3009`, and `mpp/charge/usdc/solana` is `MPP_CHARGE_USDC_SOLANA`.
The [pairings reference](./pairings.md) lists every one.
