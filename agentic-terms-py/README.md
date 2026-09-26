# integraledger-terms

The buyer gate for agents that pay, in Python: before your wallet signs anything, it confirms that the record a seller
serves hashes to the value the payment will carry, and builds the payment with that hash.

```sh
pip install integraledger-terms
```

## What it is

A seller that follows the Legal Context Protocol publishes the agreement's record, an **Agentic Transaction Record
(ATR)**, at an `https` link, and advertises its hash beside the payment request. The payment your agent signs carries
that hash, so paying is agreeing to that exact record.

That only holds if the hash in the payment is the hash of the record you can read. This package is the check that makes
sure it is. It fetches the record, computes its SHA-256, compares it with what the seller advertised, and only on a
match hands your signer a request built with that hash. After your signer answers, it reads the hash back out of what
was signed and returns the payment only if it is still the hash of the bytes you received.

It is the Python implementation of the same gate as the TypeScript package
[`@integraledger/terms`](https://www.npmjs.com/package/@integraledger/terms). Both run the same rules and pass the same
shared vectors, pairing for pairing. It holds no keys, moves no funds, and never reads the record's content: what the
record says is for you and your principal to judge.

## Key concepts

- **Agentic Transaction Record (ATR):** the agreement's record, a JSON document the seller serves.
- **ATR hash (H):** SHA-256 over the ATR's exact bytes, `0x` and 64 hex digits. It is computed over the bytes as
  received, never over a parsed and re-serialised copy.
- **Legal Context Protocol (LCP):** the pattern this package implements: the payment carries H, so paying is agreeing
  to that exact record.
- **Pairing:** a payment protocol, scheme and rail combination, such as `x402/exact/eip155/eip3009`.
- **Binding:** how H rides in a pairing's payment, the field its specification defines. This package exports one
  binding per pairing, named after its id: `X402_EXACT_EIP155_EIP3009`.
- **Buyer gate:** this package: the buyer-side check that compares the served bytes with H before anything is signed.
- **Seller:** the party serving the resource.
- **Facilitator:** the x402 role that verifies and settles. The gate never talks to one: it returns the payment to you.
- **Vectors:** the shared test cases that fix the rules byte for byte across languages.

## Install

```sh
pip install integraledger-terms
```

Python `>=3.11`. The package depends on `httpx` and `cryptography`, and is fully typed (`py.typed`).

The examples below sign with [eth-account](https://github.com/ethereum/eth-account) (`pip install eth-account`). The
gate itself never signs; any wallet that can sign the request works.

## Quickstart

The seller answered with an x402 `402 Payment Required` whose `PAYMENT-REQUIRED` document advertises H and the link.
This example uses the ATR, the document and the payer key of the shared vectors, and an `httpx.MockTransport` as a
local stand-in for the network, so it runs offline and prints the same values every time.

```python
import asyncio
from collections.abc import Mapping
from typing import Any

import httpx
from eth_account import Account
from eth_account.messages import encode_typed_data

from integraledger_terms import X402_EXACT_EIP155_EIP3009, Declined, transact

# The ATR, exactly as the seller's link serves it. The gate hashes these bytes and never parses them.
ATR = (
    '{"atrVersion":"1","id":"0f8fad5b-d9cb-469f-a165-70867728950e","x402":{"z":1.0,"a":"caf\\u00e9"},'
    '"seller":{"note":"Café — 30 días ✓"}}'
).encode()
H = "0x8b1e122580ae3f6a8c3d36a24294e1260a87bde70f597279b973e39310072938"
LINK = f"https://atr.seller.example/{H}"

# The seller's x402 payment request, advertising H and the link.
OFFER = {
    "x402Version": 2,
    "resource": {"url": "https://api.seller.example/v1/quote"},
    "accepts": [
        {
            "scheme": "exact",
            "network": "eip155:84532",
            "amount": "10000",
            "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
            "maxTimeoutSeconds": 60,
            "extra": {"name": "USDC", "version": "2"},
        }
    ],
    "extensions": {"legalContext": {"info": {"type": "sha256", "value": H, "legalContextUrl": LINK}, "schema": {}}},
}

# The published Anvil development key. Never use it for real funds.
KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"


class Wallet:
    account = "eip155:84532:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

    async def sign(self, request: Mapping[str, Any]) -> str:
        if request["kind"] != "eip712":
            raise ValueError(f"this wallet signs EIP-712 only, not {request['kind']}")
        signed = Account.sign_message(encode_typed_data(full_message=dict(request["typedData"])), KEY)
        return "0x" + bytes(signed.signature).hex()


def seller(request: httpx.Request) -> httpx.Response:
    """A stand-in for the network: the link serves the ATR."""
    return httpx.Response(200, content=ATR) if str(request.url) == LINK else httpx.Response(404)


async def main() -> None:
    async with httpx.AsyncClient(transport=httpx.MockTransport(seller)) as client:
        result = await transact(OFFER, X402_EXACT_EIP155_EIP3009, Wallet(), client)
    if isinstance(result, Declined):
        raise SystemExit(f"{result.code}: {result.detail}")
    assert result.signed is not None
    print("H           ", result.h)
    print("signed nonce", result.signed["payload"]["authorization"]["nonce"])
    print("kept bytes  ", len(result.atr_bytes))


asyncio.run(main())
```

```text output
H            0x8b1e122580ae3f6a8c3d36a24294e1260a87bde70f597279b973e39310072938
signed nonce 0x8b1e122580ae3f6a8c3d36a24294e1260a87bde70f597279b973e39310072938
kept bytes   138
```

The nonce your wallet signed is the hash of the 138 bytes the link served. Keep `result.atr_bytes` with the payment:
they are your copy of the record. To send the payment over x402's HTTP transport, put base64 of its JSON in the
`PAYMENT-SIGNATURE` header.

If the link had served one byte more, less or different, `transact` would have returned
`Declined(code="hash-mismatch", …)` and never called the signer.

## How it works

1. **Read.** The pairing's binding reads the seller's document: H, the link, and the payment options.
2. **Compare.** The gate fetches the link once, with your `httpx.AsyncClient`, and hashes the bytes it received. No
   match: a `Declined`, and no signer call.
3. **Build.** On a match, the gate builds the payment with the hash it computed, not the string the seller advertised.
4. **Finish.** The gate joins your signer's answer, reads H back out of what was signed, and returns the payment only
   when it is the hash of the compared bytes.

Every function returns a value and never raises for a protocol outcome: either its result, or a `Declined`.

## Guides

### Pay in one call: `transact`

`await transact(doc, binding, signer, fetch, *, inputs=None, agreement_signer=None)` runs the whole order: compare,
pay the agreement first where the pairing needs one, sign, finish. It returns `Transacted`:

| Field | What it is |
| --- | --- |
| `signed` | The payment to send, in the protocol's own form. `None` when the pairing gives the buyer nothing to sign. |
| `atr_bytes` | The ATR's exact bytes: your copy of the record. |
| `h` | Their SHA-256. |
| `agreement` | The agreement's `AgreementReceipt`, where an agreement was paid first. |
| `landed` | A landed receipt to keep beside the payment, for the few pairings that return one. |

`inputs` are the buyer's own values a build needs, such as a recent blockhash; `agreement_signer` pays the agreement
where a different wallet should. See the [rails guide](https://github.com/IntegraLedger/integra-agentic-terms/blob/main/docs/guides/rails.md)
for each pairing's inputs.

### Sign elsewhere: `confirm`, then `finish`

When the key lives in a hardware wallet or a signing service, split the order. `Confirmed.chosen` holds plain JSON, so
it crosses process boundaries with the bytes:

```python
import asyncio

import httpx
from eth_account import Account
from eth_account.messages import encode_typed_data

from integraledger_terms import X402_EXACT_EIP155_EIP3009, Declined, Finished, confirm, finish

ATR = (
    '{"atrVersion":"1","id":"0f8fad5b-d9cb-469f-a165-70867728950e","x402":{"z":1.0,"a":"caf\\u00e9"},'
    '"seller":{"note":"Café — 30 días ✓"}}'
).encode()
H = "0x8b1e122580ae3f6a8c3d36a24294e1260a87bde70f597279b973e39310072938"
LINK = f"https://atr.seller.example/{H}"
OFFER = {
    "x402Version": 2,
    "resource": {"url": "https://api.seller.example/v1/quote"},
    "accepts": [
        {
            "scheme": "exact",
            "network": "eip155:84532",
            "amount": "10000",
            "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
            "maxTimeoutSeconds": 60,
            "extra": {"name": "USDC", "version": "2"},
        }
    ],
    "extensions": {"legalContext": {"info": {"type": "sha256", "value": H, "legalContextUrl": LINK}, "schema": {}}},
}
KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"


def seller(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, content=ATR) if str(request.url) == LINK else httpx.Response(404)


async def main() -> None:
    # 1. Compare, and build the request with H.
    async with httpx.AsyncClient(transport=httpx.MockTransport(seller)) as client:
        confirmed = await confirm(
            OFFER, X402_EXACT_EIP155_EIP3009, "eip155:84532:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", client
        )
    if isinstance(confirmed, Declined) or confirmed.request is None:
        raise SystemExit(f"not confirmed: {confirmed}")

    # 2. Sign exactly the request, elsewhere.
    typed = encode_typed_data(full_message=dict(confirmed.request["typedData"]))
    signature = "0x" + bytes(Account.sign_message(typed, KEY).signature).hex()

    # 3. Finish from the bytes and chosen. finish recomputes H from the bytes; it trusts nothing it did not rebuild.
    done = finish(confirmed.atr_bytes, confirmed.chosen, signature, X402_EXACT_EIP155_EIP3009)
    if not isinstance(done, Finished):
        raise SystemExit(f"not finished: {done}")
    print("nonce is H:", done.signed["payload"]["authorization"]["nonce"] == H)


asyncio.run(main())
```

```text output
nonce is H: True
```

A pairing signed in two steps (a channel funding, then its first voucher) makes `finish` return `Next`: sign
`next.next` and call `finish` again with every answer so far, in order, as a list. `transact` does this for you.

### Pay the agreement first

Some payments are not a public proof of H: a card charge, a Stripe payment, a Lightning invoice, a checkout in which
the buyer signs nothing. For those pairings the seller's offer also names an **agreement URL**, an x402 resource for the
same H whose payment is a public proof. `transact` pays it first and signs the main payment only after the agreement URL
answers `200` with a receipt `{"atrHash": H, "agreed": true, "network": …, "transaction": …}`.

- The agreement URL's `402` must advertise the same H, or nothing is signed (`hash-mismatch`).
- Once the agreement payment is sent, the gate sends the same payment again after each `202`, `5xx` or timeout, within
  the agreement option's `maxTimeoutSeconds` plus 180 seconds. It never signs a second agreement payment.
- A pairing that needs an agreement and whose offer names none is declined with `agreement-not-offered`.
- `await agree(h, url, signer, fetch, atr_bytes=…, inputs=…)` runs the exchange on its own.

### Channels and sessions

In an x402 batch-settlement channel or an MPP session, one ATR covers the whole channel. The gate compares it once, at
the opening; you keep a **hold** (a JSON-ready `dict`) and sign every later voucher from it. This example opens a
channel with the vectors' two development keys and pays two more requests in it:

```python
import asyncio
from collections.abc import Mapping
from typing import Any

import httpx
from eth_account import Account
from eth_account.messages import encode_typed_data

from integraledger_terms import X402_BATCH_SETTLEMENT_EIP155, Declined, open_channel, record_charge, transact, within

ATR = (
    '{"atrVersion":"1","id":"0f8fad5b-d9cb-469f-a165-70867728950e","x402":{"z":1.0,"a":"caf\\u00e9"},'
    '"seller":{"note":"Café — 30 días ✓"}}'
).encode()
H = "0x8b1e122580ae3f6a8c3d36a24294e1260a87bde70f597279b973e39310072938"
LINK = f"https://atr.seller.example/{H}"

# The seller's batch-settlement offer: 1000 units per request, into a channel.
OFFER = {
    "x402Version": 2,
    "resource": {"url": "https://api.seller.example/v1/quote"},
    "accepts": [
        {
            "scheme": "batch-settlement",
            "network": "eip155:84532",
            "amount": "1000",
            "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
            "maxTimeoutSeconds": 3600,
            "extra": {
                "receiverAuthorizer": "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
                "withdrawDelay": 900,
                "name": "USDC",
                "version": "2",
            },
        }
    ],
    "extensions": {"legalContext": {"info": {"type": "sha256", "value": H, "legalContextUrl": LINK}, "schema": {}}},
}

# Anvil development keys: the payer funds the channel, the payer authorizer signs vouchers. Never use them for real funds.
PAYER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
AUTHORIZER_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
AUTHORIZER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"


def sign_typed(typed_data: Mapping[str, Any], key: str) -> str:
    signed = Account.sign_message(encode_typed_data(full_message=dict(typed_data)), key)
    return "0x" + bytes(signed.signature).hex()


class Wallet:
    account = "eip155:84532:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

    async def sign(self, request: Mapping[str, Any]) -> list[str]:
        if request["kind"] != "batch":
            raise ValueError(f"unexpected {request['kind']}")
        answers = []
        for each in request["requests"]:
            typed = each["typedData"]
            answers.append(sign_typed(typed, AUTHORIZER_KEY if typed["primaryType"] == "Voucher" else PAYER_KEY))
        return answers


def seller(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, content=ATR) if str(request.url) == LINK else httpx.Response(404)


async def main() -> None:
    wallet = Wallet()
    # Open: compare the ATR once, sign the deposit and the first voucher.
    async with httpx.AsyncClient(transport=httpx.MockTransport(seller)) as client:
        opened = await transact(
            OFFER, X402_BATCH_SETTLEMENT_EIP155, wallet, client, inputs={"payerAuthorizer": AUTHORIZER, "deposit": "100000"}
        )
    if isinstance(opened, Declined) or opened.signed is None:
        raise SystemExit(f"the channel did not open: {opened}")
    hold = open_channel(opened.atr_bytes, opened.signed, X402_BATCH_SETTLEMENT_EIP155)
    if isinstance(hold, Declined):
        raise SystemExit(hold.code)
    print("channel ", hold["channel"])

    # Each later request: the seller's new offer must advertise the held H.
    for charged in ("1000", "2000"):
        paid = await within(OFFER, hold, X402_BATCH_SETTLEMENT_EIP155, wallet)
        if isinstance(paid, Declined):
            raise SystemExit(paid.code)
        print("voucher up to", paid.hold["signedMax"])
        # The seller reports its cumulative charge; it may not exceed what was signed.
        recorded = record_charge(paid.hold, charged)
        if isinstance(recorded, Declined):
            raise SystemExit(recorded.code)
        hold = recorded


asyncio.run(main())
```

```text output
channel  0x9c2d7031768ecb3fe688ae307c45f2e3a3d98b0d9ce1a6afcd27131fabb67e56
voucher up to 1000
voucher up to 2000
```

The channel id is the one the TypeScript gate computes for the same inputs: both languages build the same payment.

### Confirm a payment later: `check`

`check(atr_bytes, presented, binding)` returns `Checked(h)` when a payment you hold carries, inside what was signed,
the SHA-256 of the bytes you kept. Where `finish` or `transact` returned `landed`, put it back into the payment under
`"landed"` first.

### Declines and `moved`

A decline is `Declined(code, detail, moved)`. `code` is one of twelve values; `detail` is a sentence or the protocol's
refusal code. Where your signer moved the payment itself before the gate declined (a Lightning node paid the invoice, a
signer broadcast a transaction), `moved` is `Moved(signed, atr_bytes, h)`. Keep it, and present it again rather than
signing a new payment.

| Code | Meaning |
| --- | --- |
| `pairing-not-supported` | The binding names no pairing the gate serves; `chosen` or a hold belongs to another pairing; the pairing has no channel; or the agreement URL's option is not paid with a public-proof pairing. |
| `offer-unreadable` | The seller's document, the chosen option or a build could not be read, or a recorded charge is out of range. `detail` carries the reason. |
| `no-payable-option` | No option is payable by this account, an input the build needs is missing or malformed, or `transact`'s arguments are malformed. |
| `link-not-https` | The ATR link or the agreement URL is not an `https` URL. Nothing was fetched. |
| `atr-unfetchable` | The link did not answer `200` with the bytes within 10 seconds (a redirect counts as a failure), or served a content encoding other than gzip or deflate. |
| `atr-too-large` | The ATR is larger than 1 MiB (1,048,576 bytes). |
| `hash-mismatch` | The served bytes do not hash to the advertised H; the agreement URL or a later channel challenge advertises another H; or a hold's bytes do not hash to its H. Nothing was signed. |
| `signer-failed` | Your signer raised. |
| `signed-not-bound` | What was signed does not carry the hash of the compared bytes. The payment is not returned. |
| `agreement-not-offered` | The pairing's payment is not a public proof, and the offer names no agreement URL. |
| `agreement-pending` | The agreement payment was sent and is not yet recorded, or another is already settling. |
| `agreement-failed` | The agreement URL could not be reached, or answered with something other than a receipt for this H. |

## API reference

Everything below is exported from `integraledger_terms`.

### Functions

| Export | Signature | What it does |
| --- | --- | --- |
| `transact` | `async (doc, binding, signer, fetch, *, inputs=None, agreement_signer=None) -> Transacted \| Declined` | Compare, pay the agreement first where needed, sign, finish. |
| `confirm` | `async (doc, binding, account, fetch, inputs=None) -> Confirmed \| Declined` | Read, fetch, compare, and build the signing request with H. `request` is `None` when there is nothing to sign. |
| `finish` | `(atr_bytes, chosen, signature, binding) -> Finished \| Next \| Declined` | Rebuild from `chosen` and the bytes, join the signature, and return the payment only when what was signed carries H. |
| `check` | `(atr_bytes, presented, binding) -> Checked \| Declined` | Confirm a held payment carries the hash of the kept bytes. |
| `agree` | `async (h, url, signer, fetch, *, atr_bytes, inputs=None, ns=None) -> Agreed \| Declined` | Pay an agreement URL for H and return its receipt. |
| `open_channel` | `(atr_bytes, opened, binding, landed=None) -> ChannelHold \| Declined` | Hold a channel opened for the compared ATR. |
| `within` | `async (doc, hold, binding, signer, refund=None, inputs=None) -> Within \| Declined` | Sign a later voucher, or a refund with `refund`, in a held channel. |
| `record_charge` | `(hold, charged_cumulative_amount) -> ChannelHold \| Declined` | Record the seller's cumulative charge, between the last recorded and the most signed. |
| `atr_hash` | `(data: bytes) -> AtrHash` | SHA-256 of the bytes, `0x` and 64 lower-case hex digits. |
| `hash_equals` | `(a: str, b: str) -> bool` | Compares two hashes as 32 decoded bytes, in either case; `False` when either is malformed. |

`fetch` is an `httpx.AsyncClient`. The gate asks it for one `GET` of the link, with `Accept-Encoding: identity` and no
redirect, and decodes a gzip or deflate body with the size bound applied to the decoded bytes.

### Results and types

| Export | What it is |
| --- | --- |
| `Transacted` | `signed`, `atr_bytes`, `h`, `agreement`, `landed`. |
| `Confirmed` | `chosen`, `request` (a `dict`, or `None`), `atr_bytes`, `h`, `agreement` (the URL, or `None`). |
| `Finished` | `signed`, `h`, `landed`. |
| `Next` | `next` (the next request) and `h`, for a payment signed in steps. |
| `Checked` | `h`. |
| `Agreed` | `receipt`. |
| `AgreementReceipt` | `atr_hash`, `agreed`, `network`, `transaction`. |
| `Within` | `signed` and the updated `hold`. |
| `ChannelHold` | A `dict`: `pairing`, `network`, `channel`, `h`, `atr` (base64), `opening`, `charged`, `signedMax`. |
| `Declined` | `code`, `detail`, `moved`. |
| `DeclineCode` | The twelve codes in the table above. |
| `Chosen` | `pairing`, `choice`, `ref`: what the gate chose to pay, as JSON. |
| `Signer` | A protocol: an `account` string (CAIP-10) and `async def sign(self, request) -> Signature`. |
| `Binding` | A protocol: `id`, `public_proof`, `read`, `build`, `bound`. |
| `Advertised`, `Step`, `Refusal`, `Unsigned`, `BatchUnsigned`, `ChannelRef` | The values a binding and the gate exchange, for code that implements a binding. |
| `AtrHash`, `Json`, `Inputs`, `Signature` | Aliases: `str`, `Mapping[str, Any]`, `Mapping[str, Any]`, `Any`. |
| `MAX_ATR_BYTES` | `1048576`. |

A signer receives each request with every byte string as `0x` and lower-case hex, and answers with byte strings in the
same form. The [signers guide](https://github.com/IntegraLedger/integra-agentic-terms/blob/main/docs/guides/signers.md)
lists every request kind and the answer it takes.

## Supported pairings

Each pairing is a module-level binding constant. The list is generated from the TypeScript registry and checked against
this package's exports, so both languages serve the same pairings. "Agreement payment first" marks the pairings whose
payment is not itself a public proof of H.

<!-- pairings:python:start -->
| Rail | Pairing | Python binding | Buyer signs H | Agreement payment first |
| --- | --- | --- | --- | --- |
| EVM | `mpp/charge/evm/authorization` | `MPP_CHARGE_EVM_AUTHORIZATION` | yes | no |
| EVM | `mpp/charge/evm/hash` | `MPP_CHARGE_EVM_HASH` | no | yes |
| EVM | `mpp/charge/evm/permit2` | `MPP_CHARGE_EVM_PERMIT2` | yes | no |
| EVM | `mpp/charge/evm/transaction` | `MPP_CHARGE_EVM_TRANSACTION` | no | yes |
| EVM | `mpp/charge/usdc/evm` | `MPP_CHARGE_USDC_EVM` | yes | no |
| EVM | `mpp/charge/usdc/gateway` | `MPP_CHARGE_USDC_GATEWAY` | yes | no |
| EVM | `mpp/session/evm` | `MPP_SESSION_EVM` | yes | no |
| EVM | `x402/auth-capture/eip155/eip3009` | `X402_AUTH_CAPTURE_EIP155_EIP3009` | yes | no |
| EVM | `x402/auth-capture/eip155/permit2` | `X402_AUTH_CAPTURE_EIP155_PERMIT2` | yes | no |
| EVM | `x402/batch-settlement/eip155` | `X402_BATCH_SETTLEMENT_EIP155` | yes | no |
| EVM | `x402/exact/eip155/eip3009` | `X402_EXACT_EIP155_EIP3009` | yes | no |
| EVM | `x402/exact/eip155/erc7710` | `X402_EXACT_EIP155_ERC7710` | no | yes |
| EVM | `x402/exact/eip155/erc7710-salt` | `X402_EXACT_EIP155_ERC7710_SALT` | yes | no |
| EVM | `x402/exact/eip155/permit2` | `X402_EXACT_EIP155_PERMIT2` | yes | no |
| EVM | `x402/upto/eip155/permit2` | `X402_UPTO_EIP155_PERMIT2` | yes | no |
| Tempo | `mpp/charge/tempo/memo` | `MPP_CHARGE_TEMPO_MEMO` | no | no |
| Tempo | `mpp/charge/tempo/push` | `MPP_CHARGE_TEMPO_PUSH` | no | no |
| Tempo | `mpp/session/tempo` | `MPP_SESSION_TEMPO` | yes | no |
| Tempo | `mpp/subscription/tempo` | `MPP_SUBSCRIPTION_TEMPO` | yes | no |
| Solana | `mpp/charge/solana` | `MPP_CHARGE_SOLANA` | yes | no |
| Solana | `mpp/charge/usdc/solana` | `MPP_CHARGE_USDC_SOLANA` | yes | no |
| Solana | `mpp/session/solana` | `MPP_SESSION_SOLANA` | no | no |
| Solana | `x402/batch-settlement/solana` | `X402_BATCH_SETTLEMENT_SOLANA` | yes | no |
| Solana | `x402/exact/solana` | `X402_EXACT_SOLANA` | yes | no |
| Solana | `x402/upto/solana` | `X402_UPTO_SOLANA` | yes | no |
| Stellar | `mpp/charge/stellar` | `MPP_CHARGE_STELLAR` | no | no |
| Stellar | `x402/exact/stellar` | `X402_EXACT_STELLAR` | no | no |
| XRP Ledger | `mpp/charge/xrpl` | `MPP_CHARGE_XRPL` | yes | no |
| XRP Ledger | `mpp/session/xrpl` | `MPP_SESSION_XRPL` | yes | no |
| XRP Ledger | `x402/exact/xrpl` | `X402_EXACT_XRPL` | yes | no |
| Hedera | `mpp/charge/hedera` | `MPP_CHARGE_HEDERA` | no | no |
| Hedera | `mpp/session/hedera` | `MPP_SESSION_HEDERA` | yes | no |
| Hedera | `x402/exact/hedera` | `X402_EXACT_HEDERA` | yes | no |
| Hedera | `x402/exact/hedera/transfer-executor` | `X402_EXACT_HEDERA_TRANSFER_EXECUTOR` | no | yes |
| Algorand | `x402/exact/algorand` | `X402_EXACT_ALGORAND` | yes | no |
| Aptos | `x402/exact/aptos` | `X402_EXACT_APTOS` | no | yes |
| Sui | `x402/exact/sui` | `X402_EXACT_SUI` | yes | no |
| NEAR | `mpp/charge/nearintents` | `MPP_CHARGE_NEARINTENTS` | no | yes |
| NEAR | `x402/exact/near` | `X402_EXACT_NEAR` | yes | no |
| Starknet | `x402/exact/starknet` | `X402_EXACT_STARKNET` | yes | no |
| Polkadot | `x402/exact/polkadot/lcp-assets-remark` | `X402_EXACT_POLKADOT_LCP_ASSETS_REMARK` | yes | no |
| TRON | `x402/exact/tron/lcp-trc20-memo` | `X402_EXACT_TRON_LCP_TRC20_MEMO` | yes | no |
| TON | `x402/exact/tvm` | `X402_EXACT_TVM` | yes | no |
| Cardano | `x402/exact/cardano` | `X402_EXACT_CARDANO` | yes | no |
| Casper | `x402/exact/casper` | `X402_EXACT_CASPER` | yes | no |
| Concordium | `x402/exact/ccd` | `X402_EXACT_CCD` | yes | no |
| Stacks | `mpp/charge/usdc/stacks` | `MPP_CHARGE_USDC_STACKS` | yes | no |
| Lightning | `mpp/charge/lightning` | `MPP_CHARGE_LIGHTNING` | no | yes |
| Lightning | `mpp/session/lightning` | `MPP_SESSION_LIGHTNING` | no | yes |
| Lightning | `x402/exact/lnbtc` | `X402_EXACT_LNBTC` | no | yes |
| Lightning | `x402/exact/lnbtc/invoice-named` | `X402_EXACT_LNBTC_INVOICE_NAMED` | no | yes |
| Cloudflare | `x402/batch-settlement/cloudflare` | `X402_BATCH_SETTLEMENT_CLOUDFLARE` | yes | yes |
| Card | `card/mastercard-vi/autonomous` | `CARD_MASTERCARD_VI_AUTONOMOUS` | yes | yes |
| Card | `card/mastercard-vi/immediate` | `CARD_MASTERCARD_VI_IMMEDIATE` | yes | yes |
| Card | `card/seller-reference` | `CARD_SELLER_REFERENCE` | no | yes |
| Card | `card/visa-tap` | `CARD_VISA_TAP` | yes | yes |
| Card | `mpp/charge/card` | `MPP_CHARGE_CARD` | no | yes |
| Stripe | `mpp/charge/stripe` | `MPP_CHARGE_STRIPE` | no | yes |
| Stripe | `mpp/subscription/stripe` | `MPP_SUBSCRIPTION_STRIPE` | no | yes |
| Mandate | `ap2/checkout-mandate` | `AP2_CHECKOUT_MANDATE` | yes | yes |
| Mandate | `ucp/booking/ap2-mandate` | `UCP_BOOKING_AP2_MANDATE` | yes | yes |
| Mandate | `ucp/checkout/ap2-mandate` | `UCP_CHECKOUT_AP2_MANDATE` | yes | yes |
| Checkout | `ack/payment-request` | `ACK_PAYMENT_REQUEST` | no | yes |
| Checkout | `acp/checkout/delegated` | `ACP_CHECKOUT_DELEGATED` | no | yes |
| Checkout | `acp/checkout/undelegated` | `ACP_CHECKOUT_UNDELEGATED` | no | yes |
| Checkout | `ucp/booking/unsigned` | `UCP_BOOKING_UNSIGNED` | no | yes |
| Checkout | `ucp/checkout/unsigned` | `UCP_CHECKOUT_UNSIGNED` | no | yes |
<!-- pairings:python:end -->

## Security model

What the gate guarantees, in the code:

- **Nothing is signed before the comparison.** The signer is called only after SHA-256 of the served bytes equals the
  advertised H, compared as 32 decoded bytes.
- **The payment carries the computed hash.** The build takes the hash the gate computed, not the advertised string.
- **What was signed is read back.** `finish` returns a payment only when the binding reads, from what was signed, the
  hash of the compared bytes. For a pairing whose payment is not a public proof, the payment is returned only after the
  agreement's receipt for that hash.
- **One bounded fetch.** One `GET` of an `https` link, no redirect, one 10-second deadline over headers and body, at most
  1 MiB of decoded body.
- **Exact bytes.** The ATR is hashed as received and returned as received. It is never parsed.
- **No keys.** The gate hands requests to your signer and holds nothing that could sign.

What it does not do:

- It does not read or judge the ATR's content.
- It does not check amount, payee, asset, timing or payer against the ATR. A discrepancy is between the parties.
- It carries no business or legal logic.
- It does not store the ATR, talk to a facilitator, or settle a payment.

## Test vectors and conformance

The rules are fixed by the shared vectors that the TypeScript package `@integraledger/lcp` ships in its `vectors/`
directory: the buyer rows of `buyer.json` (the hash, a record changed by one byte, the fetch bounds, the agreement
exchange) and each pairing's file (the request it builds and the payment it completes). This package's test suite runs
every one on Python 3.11 and 3.14, and the TypeScript gate runs the same files, so both compute the same hashes, build
the same requests and give the same declines. The tests read the vectors from the repository, so they run from a
checkout, not from the published package.

## Requirements

- Python `>=3.11`.
- `httpx` and `cryptography`, installed with the package.
- A signer for the pairings you pay.

## Contributing

See the [repository README](https://github.com/IntegraLedger/integra-agentic-terms#readme) and
[CONTRIBUTING.md](https://github.com/IntegraLedger/integra-agentic-terms/blob/main/CONTRIBUTING.md).

## License

Apache-2.0. See [LICENSE](https://github.com/IntegraLedger/integra-agentic-terms/blob/main/agentic-terms-py/LICENSE).
