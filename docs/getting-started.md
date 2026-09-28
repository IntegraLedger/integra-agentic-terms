---
title: Getting started
description: Install the buyer gate, pay a seller's x402 request only when the served ATR matches its hash, and watch the gate refuse a tampered record.
---

This page takes you from nothing to a signed payment in TypeScript and in Python. Both examples use the seller document,
the ATR and the payer key from the shared [vectors](./reference/vectors.md), and a local stand-in for the network, so
they run offline and print the same values every time.

## Requirements

- **TypeScript:** Node.js `>=26.10.0`. The package is ESM only.
- **Python:** Python `>=3.11`.

## Install

```sh
npm install @integraledger/terms @integraledger/lcp
```

`@integraledger/terms` is the gate. `@integraledger/lcp` exports the bindings you pass to it, one per pairing.

```sh
pip install integraledger-terms
```

The Python package is self-contained: its bindings are part of it.

The examples below also use a wallet library to sign: [viem](https://viem.sh) in TypeScript
(`npm install viem`) and [eth-account](https://github.com/ethereum/eth-account) in Python
(`pip install eth-account`). The gate itself never signs; any wallet that can sign the request works.

## Pay a seller, in TypeScript

The seller answered a request with an x402 `402 Payment Required`. Its `PAYMENT-REQUIRED` document offers one option on
Base Sepolia (`eip155:84532`) and, in `extensions.legalContext`, advertises H and the link to the ATR.

```ts
import { transact, type Fetch, type Signer } from "@integraledger/terms";
import { exactEip3009, type Eip3009Payment } from "@integraledger/lcp/x402";
import { privateKeyToAccount } from "viem/accounts";

// The ATR, exactly as the seller's link serves it. The gate hashes these bytes and never parses them.
const atr = new TextEncoder().encode(
  '{"atrVersion":"1","id":"0f8fad5b-d9cb-469f-a165-70867728950e","x402":{"z":1.0,"a":"caf\\u00e9"},"seller":{"note":"Café — 30 días ✓"}}',
);
const H = "0x8b1e122580ae3f6a8c3d36a24294e1260a87bde70f597279b973e39310072938";
const link = `https://atr.seller.example/${H}`;

// The seller's x402 payment request, advertising H and the link.
const offer = {
  x402Version: 2,
  resource: { url: "https://api.seller.example/v1/quote" },
  accepts: [
    {
      scheme: "exact",
      network: "eip155:84532",
      amount: "10000",
      asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
      payTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
      maxTimeoutSeconds: 60,
      extra: { name: "USDC", version: "2" },
    },
  ],
  extensions: {
    legalContext: { info: { type: "sha256", value: H, legalContextUrl: link }, schema: {} },
  },
};

// A stand-in for the network: the link serves the ATR. In production, pass globalThis.fetch.
const fetch: Fetch = async (url) => (url === link ? new Response(atr) : new Response(null, { status: 404 }));

// The published Anvil development key. Never use it for real funds.
const wallet = privateKeyToAccount("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const signer: Signer = {
  account: `eip155:84532:${wallet.address}`,
  async sign(request) {
    if (request.kind !== "eip712") throw new Error(`this wallet signs EIP-712 only, not ${request.kind}`);
    return wallet.signTypedData(request.typedData as Parameters<typeof wallet.signTypedData>[0]);
  },
};

const result = await transact(offer, exactEip3009, signer, fetch);
if ("decline" in result) throw new Error(`${result.decline.code}: ${result.decline.detail}`);
if ("approve" in result) throw new Error("this pairing pays no agreement first");

const payment = result.signed as Eip3009Payment;
console.log("H          ", result.h);
console.log("signed nonce", payment.payload.authorization.nonce);
console.log("kept bytes ", result.bytes.length);

// x402 over HTTP sends the payment as base64 of its JSON, in the PAYMENT-SIGNATURE header.
const header = btoa(JSON.stringify(result.signed));
console.log("header     ", header.length > 0 ? "ready" : "empty");
```

```text output
H           0x8b1e122580ae3f6a8c3d36a24294e1260a87bde70f597279b973e39310072938
signed nonce 0x8b1e122580ae3f6a8c3d36a24294e1260a87bde70f597279b973e39310072938
kept bytes  138
header      ready
```

What happened:

1. `transact` read the offer through the `x402/exact/eip155/eip3009` binding and chose the option on the signer's
   network.
2. It fetched the link and computed SHA-256 over the 138 bytes it received. The result matched the advertised H.
3. It built an EIP-3009 `TransferWithAuthorization` whose `nonce` is that hash, and handed it to your signer.
4. It completed the payment with the signature, read the nonce back out of what was signed, and returned the payment
   because the nonce is the hash of the bytes it compared.

Keep `result.bytes` with the payment. They are your copy of the record, and the hash in the payment shows which record
it was.

## Watch the gate refuse

Change one byte of what the link serves: `30 días` becomes `31 días`. The seller still advertises the same H.

```ts
import { transact, type Fetch, type Signer } from "@integraledger/terms";
import { exactEip3009 } from "@integraledger/lcp/x402";

const H = "0x8b1e122580ae3f6a8c3d36a24294e1260a87bde70f597279b973e39310072938";
const link = `https://atr.seller.example/${H}`;
const offer = {
  x402Version: 2,
  resource: { url: "https://api.seller.example/v1/quote" },
  accepts: [
    {
      scheme: "exact",
      network: "eip155:84532",
      amount: "10000",
      asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
      payTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
      maxTimeoutSeconds: 60,
      extra: { name: "USDC", version: "2" },
    },
  ],
  extensions: { legalContext: { info: { type: "sha256", value: H, legalContextUrl: link }, schema: {} } },
};

// The link serves a record that differs from the advertised one by one byte.
const tampered = new TextEncoder().encode(
  '{"atrVersion":"1","id":"0f8fad5b-d9cb-469f-a165-70867728950e","x402":{"z":1.0,"a":"caf\\u00e9"},"seller":{"note":"Café — 31 días ✓"}}',
);
const fetch: Fetch = async () => new Response(tampered);

let calls = 0;
const signer: Signer = {
  account: "eip155:84532:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
  async sign() {
    calls++;
    return "0x";
  },
};

const result = await transact(offer, exactEip3009, signer, fetch);
console.log("decline     ", "decline" in result ? result.decline.code : "none");
console.log("signer calls", calls);
```

```text output
decline      hash-mismatch
signer calls 0
```

The signer was never called. A decline is a value, never an exception: every gate function returns either its result
or `{ decline: { code, detail } }`. The [declines reference](./reference/declines.md) lists every code.

## Pay a seller, in Python

The same payment, with `httpx` for the network and `eth-account` as the wallet.

```python
import asyncio

import httpx
from eth_account import Account
from eth_account.messages import encode_typed_data

from integraledger_terms import X402_EXACT_EIP155_EIP3009, Declined, transact

# The ATR, exactly as the seller's link serves it.
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

# The published Anvil development key. Never use it for real funds.
KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"


class Wallet:
    account = "eip155:84532:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

    async def sign(self, request):
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

In production, pass an `httpx.AsyncClient()` of your own. The gate asks it for one `GET` of the link, with no redirect.

## Next

- [Concepts](./concepts.md): the record, the hash, pairings, bindings and the gate.
- [Pay with the gate](./guides/pay-with-the-gate.md): `transact`, and `confirm` then `finish` for a signer that
  lives elsewhere.
- [Signers](./guides/signers.md): every kind of signing request, and what your signer returns for each.
- [Rails](./guides/rails.md): what each rail needs from you.
- [MCP server](./guides/mcp.md): give an agent the gate as tools.
