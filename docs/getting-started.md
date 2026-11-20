---
title: Getting started
description: Install the buyer gate, pay a seller's x402 request only when the served ATR matches its hash, and watch the gate refuse a tampered record.
---

This page is for a developer new to the buyer gate. It takes you from nothing to a signed payment in TypeScript and in
Python, and then to a live seller. The first examples use the seller document, the ATR and the payer key from the
shared [vectors](./reference/vectors.md), and a local stand-in for the network, so they run offline and print the same
values every time.

## Requirements

- **TypeScript:** Node.js `>=24.22.1`. The package is ESM only.
- **Python:** Python `>=3.11`.

## Install

```sh
npm install @integraledger/terms@0.5.3 @integraledger/lcp@0.6.3
```

`@integraledger/terms` is the gate. `@integraledger/lcp` exports the bindings you pass to it, one per pairing.

```sh
pip install integraledger-terms==0.5.3
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

// The ATR, exactly as the seller's link serves it. The gate hashes and parses these bytes, never a copy.
const atr = new TextEncoder().encode(
  '{"atrVersion":"1","id":"0f8fad5b-d9cb-469f-a165-70867728950e","x402":{"z":1.0,"a":"caf\\u00e9"},"seller":{"note":"Café — 30 días ✓"}}',
);
const H = "0x8b1e122580ae3f6a8c3d36a24294e1260a87bde70f597279b973e39310072938";
const link = `https://atr.seller.example/${crypto.randomUUID()}`;

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

const result = await transact(offer, exactEip3009, signer, fetch, {
  // The request the seller's 402 answered, exactly as your agent sent it: the target is origin-form, never the full URL.
  resourceRequest: { method: "GET", target: "/v1/quote", body: new Uint8Array() },
  // Asked once for each signing, before the signer is called, with what the signature grants.
  approver: (toSign) => {
    const { amount, payees, validity } = toSign.summary;
    console.log("approve    ", amount, "to", payees[0]?.account, "payable in", validity.unit);
    return true;
  },
});
if ("decline" in result) throw new Error(`${result.decline.code}: ${result.decline.detail}`);
if ("approve" in result || "charge" in result || "agreementChallenges" in result) {
  throw new Error("this pairing pays no agreement first");
}

const payment = result.signed as Eip3009Payment;
console.log("H          ", result.h);
console.log("signed nonce", payment.payload.authorization.nonce);
console.log("kept bytes ", result.bytes.length);

// x402 over HTTP sends the payment as base64 of the UTF-8 bytes of its JSON, in the PAYMENT-SIGNATURE header.
const header = Buffer.from(JSON.stringify(result.signed), "utf8").toString("base64");
console.log("header     ", header.length > 0 ? "ready" : "empty");
```

```text output
approve     10000 to 0x209693Bc6afc0C5328bA36FaF03C514EF312287C payable in seconds
H           0x8b1e122580ae3f6a8c3d36a24294e1260a87bde70f597279b973e39310072938
signed nonce 0x8b1e122580ae3f6a8c3d36a24294e1260a87bde70f597279b973e39310072938
kept bytes  138
header      ready
```

What happened:

1. `transact` read the offer through the `x402/exact/eip155/eip3009` binding and chose the option on the signer's
   network.
2. It fetched the link and computed SHA-256 over the 138 bytes it received. The result matched the advertised H.
3. It parsed those bytes. Their `x402` member, the binding slot, lists no options and holds no request commitment, so
   there was nothing to hold the option or `resourceRequest` to.
4. It built an EIP-3009 `TransferWithAuthorization` whose `nonce` is that hash, computed its summary from the typed data
   (the amount, the payee, the asset, the network and the `validAfter` to `validBefore` window), found the window
   within the 600-second ceiling, and asked your approver.
5. On `true`, it handed the request to your signer, completed the payment with the signature, read the nonce back out
   of what was signed, and returned the payment because the nonce is the hash of the bytes it compared.

Keep `result.bytes` with the payment. They are your copy of the record, and the hash in the payment shows which record
it was.

## Against a live seller

Against a real seller you make the request yourself, decode its `402`, choose the binding of the option you pay, and
send the payment `transact` returns. Everything this needs is exported by `@integraledger/lcp`. Its x402 headers are
version 2: a version-1 document is refused `x402/not-v2`.

```ts no-run
import { transact, type Signer, type ToSign } from "@integraledger/terms";
import { BINDINGS, isRefusal, pairingOf } from "@integraledger/lcp";
import {
  decodePaymentRequired,
  encodeHeader,
  PAYMENT_REQUIRED,
  PAYMENT_SIGNATURE,
  type PaymentPayload,
} from "@integraledger/lcp/x402";

declare const signer: Signer; // your wallet, as above
declare function yourPolicy(toSign: ToSign): Promise<boolean>; // your agent's decision, or its principal's

const url = "https://api.seller.example/v1/quote?city=Paris";

// 1. Make the request. A seller that asks for payment answers 402, with its payment request in PAYMENT-REQUIRED.
const first = await fetch(url);
if (first.status !== 402) throw new Error(`no payment asked: ${first.status}`);
const offer = decodePaymentRequired(first.headers.get(PAYMENT_REQUIRED));
if (isRefusal(offer)) throw new Error(offer.code);

// 2. The option on your signer's network, and the binding of its pairing.
const network = signer.account.split(":").slice(0, 2).join(":");
const option = offer.accepts.find((o) => o.network === network);
const pairing = option === undefined ? undefined : pairingOf(option);
const binding = BINDINGS.find((b) => b.id === pairing);
if (binding === undefined) throw new Error("no option this signer can pay");

// 3. Compare, check, show and sign. resourceRequest is the request exactly as sent, its target origin-form.
const { pathname, search } = new URL(url);
const result = await transact(offer, binding, signer, globalThis.fetch, {
  approver: yourPolicy,
  resourceRequest: { method: "GET", target: pathname + search, body: new Uint8Array() },
});
if ("decline" in result) throw new Error(`${result.decline.code}: ${result.decline.detail}`);
if ("approve" in result || "charge" in result || "agreementChallenges" in result) {
  throw new Error("this offer is paid after an agreement: see the agreement payments guide");
}
if (result.signed === null) throw new Error("nothing to sign: complete the payment through the protocol's own flow");

// 4. Send the payment on a repeat of the same request.
const header = encodeHeader(result.signed as PaymentPayload);
if (isRefusal(header)) throw new Error(header.code);
const paid = await fetch(url, { headers: { [PAYMENT_SIGNATURE]: header } });
console.log("paid:", paid.status);

// 5. Keep result.bytes (your copy of the record), result.h and result.signed.
```

- A decline means nothing was signed, unless it carries `moved`; the
  [declines reference](./reference/declines.md) says what to do for each code.
- Where the result is `approve`, `ToReturn` or `AgreementChallenges`, the pairing is paid after an agreement: the
  [agreement payments guide](./guides/agreement-payments.md) continues from there.
- `globalThis.fetch` reaches any address your process can, and the seller chooses the link the gate fetches: read
  [The network](./security-model.md#the-network) before you deploy.

## Watch the gate refuse

Change one byte of what the link serves: `30 días` becomes `31 días`. The seller still advertises the same H.

```ts
import { transact, type Fetch, type Signer } from "@integraledger/terms";
import { exactEip3009 } from "@integraledger/lcp/x402";

const H = "0x8b1e122580ae3f6a8c3d36a24294e1260a87bde70f597279b973e39310072938";
const link = `https://atr.seller.example/${crypto.randomUUID()}`;
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

let asked = 0;
const result = await transact(offer, exactEip3009, signer, fetch, {
  resourceRequest: { method: "GET", target: "/v1/quote", body: new Uint8Array() },
  approver: () => {
    asked++;
    return true;
  },
});
console.log("decline     ", "decline" in result ? result.decline.code : "none");
console.log("approver    ", asked);
console.log("signer calls", calls);
```

```text output
decline      hash-mismatch
approver     0
signer calls 0
```

Neither the approver nor the signer was called. A decline is a value, never an exception: every gate function returns either its result
or `{ decline: { code, detail } }`. The [declines reference](./reference/declines.md) lists every code.

## Pay a seller, in Python

The same payment, with `httpx` for the network and `eth-account` as the wallet.

```python
import asyncio
import uuid

import httpx
from eth_account import Account
from eth_account.messages import encode_typed_data

from integraledger_terms import X402_EXACT_EIP155_EIP3009, Declined, ToSign, Transacted, transact

# The ATR, exactly as the seller's link serves it.
ATR = (
    '{"atrVersion":"1","id":"0f8fad5b-d9cb-469f-a165-70867728950e","x402":{"z":1.0,"a":"caf\\u00e9"},'
    '"seller":{"note":"Café — 30 días ✓"}}'
).encode()
H = "0x8b1e122580ae3f6a8c3d36a24294e1260a87bde70f597279b973e39310072938"
LINK = f"https://atr.seller.example/{uuid.uuid4()}"

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


def approver(to_sign: ToSign) -> bool:
    """Asked once for each signing, before the signer is called, with what the signature grants."""
    summary = to_sign.summary
    print("approve     ", summary.amount, "to", summary.payees[0].account, "payable in", summary.validity.unit)
    return True


async def main() -> None:
    async with httpx.AsyncClient(transport=httpx.MockTransport(seller)) as client:
        result = await transact(
            OFFER,
            X402_EXACT_EIP155_EIP3009,
            Wallet(),
            client,
            approver=approver,
            resource_request={"method": "GET", "target": "/v1/quote", "body": b""},
        )
    if isinstance(result, Declined):
        raise SystemExit(f"{result.code}: {result.detail}")
    assert isinstance(result, Transacted) and result.signed is not None
    print("H           ", result.h)
    print("signed nonce", result.signed["payload"]["authorization"]["nonce"])
    print("kept bytes  ", len(result.atr_bytes))


asyncio.run(main())
```

```text output
approve      10000 to 0x209693Bc6afc0C5328bA36FaF03C514EF312287C payable in seconds
H            0x8b1e122580ae3f6a8c3d36a24294e1260a87bde70f597279b973e39310072938
signed nonce 0x8b1e122580ae3f6a8c3d36a24294e1260a87bde70f597279b973e39310072938
kept bytes   138
```

In production, pass an `httpx.AsyncClient()` of your own. The gate asks it for one `GET` of the link, with no redirect,
and applies no address policy of its own: see [The network](./security-model.md#the-network).

## Next

- [Concepts](./concepts.md): the record, the hash, pairings, bindings and the gate.
- [Pay with the gate](./guides/pay-with-the-gate.md): `transact`, and `confirm` then `finish` for a signer that
  lives elsewhere.
- [Signers](./guides/signers.md): every kind of signing request, and what your signer returns for each.
- [Rails](./guides/rails.md): what each rail needs from you.
- [MCP server](./guides/mcp.md): give an agent the gate as tools.
- [Security model](./security-model.md): what the gate guarantees, and what it leaves to you.
