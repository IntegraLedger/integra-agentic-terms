---
title: MCP server
description: Give any MCP client the buyer gate as tools, install the skill that tells the agent how to use them, and serve the tools with your own signer.
---

`@integraledger/terms-mcp` serves the buyer gate's operations as [Model Context Protocol](https://modelcontextprotocol.io)
tools, and ships a skill that tells an agent how to use them. Each tool call is one call of `@integraledger/terms`; the
server adds the transport, the words an agent reads, a `mac` on each `chosen`, opening and hold it returns (valid only
in the same server process), the agreement receipt `atr_confirm` requires before it returns a `request`, the host's
ceilings and floors, and `atr_transact`'s approve-then-sign exchange.

This guide is for a developer who connects an agent to these tools or serves them with a wallet. By its end the server
and the skill are installed, you know the agent's flow for one payment, and you can serve the tools with your own
signer.

## Install the server

Most MCP clients take a configuration like this:

```json
{
  "mcpServers": {
    "terms": {
      "command": "npx",
      "args": ["-y", "@integraledger/terms-mcp@0.5.0"]
    }
  }
}
```

`npx` runs the package's `terms-mcp` binary, which serves the tools over stdio with no signer. It needs Node.js
`>=24.22.1`. Its `serverInfo` name is `integraledger-terms`.

## Install the skill

The skill is `skills/confirming-the-atr-hash-before-paying/SKILL.md` in the package. Copy its folder into your agent's
skills directory (for Claude Code, `.claude/skills/`), or paste the file into the agent's instructions:

```sh
npm install @integraledger/terms-mcp@0.5.0
cp -r node_modules/@integraledger/terms-mcp/skills/confirming-the-atr-hash-before-paying .claude/skills/
```

The skill's description tells the agent when it applies: before approving any payment to a seller whose payment
request advertises an ATR hash.

## What the agent does

With `terms-mcp`, the agent's own wallet signs. For one payment:

1. **Confirm.** Call `atr_confirm` with the `pairing`, the seller's `document` (for x402, the object the
   `PAYMENT-REQUIRED` header's base64 decodes to; for MPP, a list with one object per `WWW-Authenticate: Payment`
   challenge, its auth-params as members), the payer `account` in CAIP-10 form and `resourceRequest`, the request the
   402 answered: over HTTP `{ method, target, body, headers? }`, `target` the origin-form request-target (the path and
   query, such as `/v1/quote?tier=1`, never the full URL) and `body` the body's bytes as padded standard base64 (`""`
   for none), over MCP `{ name, arguments? }`. Where the ATR holds a commitment to the request, the gate declines
   `request-mismatch` for any other. On a match, the result carries the ATR, its hash, `chosen`, `request`, the exact
   thing to sign, and `summary`, every authority signing it grants.
2. **Read the summary, then sign.** Read `summary` (the amount, the payees, the asset, the network, how long the payment
   stays payable), and only if the agent approves it, have the wallet sign `request` unchanged. The
   [signers guide](./signers.md) lists every kind.
3. **Finish.** Call `atr_finish` with the `pairing`, `atr.base64`, `chosen` unchanged, and the wallet's answer as
   `signature`. The result is `signed`, the payment to send, only when the pairing reads H from the completed payment,
   or, where the proof is the agreement payment, without that reading.
4. **Send** `signed` as the protocol sends a payment.

A confirmed result, abridged (the long `typedData.types`, the echoed document and `mac`'s 64 hex digits are shortened):

```json
{
  "atrHash": "0x8b1e122580ae3f6a8c3d36a24294e1260a87bde70f597279b973e39310072938",
  "atr": {
    "base64": "eyJhdHJWZXJzaW9uIjoiMSIsImlkIjoiMGY4ZmFkNWItZDljYi00NjlmLWExNjUtNzA4Njc3Mjg5NTBlIiwieDQwMiI6eyJ6IjoxLjAsImEiOiJjYWZcdTAwZTkifSwic2VsbGVyIjp7Im5vdGUiOiJDYWbDqSDigJQgMzAgZMOtYXMg4pyTIn19",
    "utf8": "{\"atrVersion\":\"1\",\"id\":\"0f8fad5b-d9cb-469f-a165-70867728950e\",\"x402\":{\"z\":1.0,\"a\":\"caf\\u00e9\"},\"seller\":{\"note\":\"Café — 30 días ✓\"}}"
  },
  "chosen": {
    "pairing": "x402/exact/eip155/eip3009",
    "choice": {
      "required": { "x402Version": 2, "resource": { "url": "https://api.seller.example/v1/quote" } },
      "accepted": { "scheme": "exact", "network": "eip155:84532" },
      "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
      "now": 1790438346
    },
    "ref": "abKt2A5-ljuE6ab515O0H8AIX4w_r4ud",
    "mac": "0xadf8…f376"
  },
  "request": {
    "kind": "eip712",
    "typedData": {
      "domain": { "name": "USDC", "version": "2", "chainId": 84532, "verifyingContract": "0x036CbD53842c5426634e7929541eC2318f3dCF7e" },
      "primaryType": "TransferWithAuthorization",
      "message": {
        "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        "to": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
        "value": "10000",
        "validAfter": "0",
        "validBefore": "1790438406",
        "nonce": "0x8b1e122580ae3f6a8c3d36a24294e1260a87bde70f597279b973e39310072938"
      }
    }
  },
  "summary": {
    "amount": "10000",
    "payees": [{ "account": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C", "amount": "10000" }],
    "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    "network": "eip155:84532",
    "validity": { "notBefore": "0", "notAfter": "1790438406", "unit": "seconds" },
    "atr": { "base64": "eyJhdHJWZXJzaW9uIjoiMSIs…", "utf8": "{\"atrVersion\":\"1\",…" }
  }
}
```

The signed `nonce` is `atrHash`, and `summary` is read from the typed data the wallet signs. The agent passes `chosen` back to `atr_finish` exactly as it came.

### Payments signed in steps

If `atr_finish` returns `next`, it returns its `summary` beside it, which names every authority signing it grants: the
agent reads it, the wallet signs `next`, and the agent calls `atr_finish` again with every answer so far, in order, as a
list.

### Nothing to sign

If `request` is `null`, the wallet signs nothing. For `x402/batch-settlement/cloudflare`, whose build is itself the
payment, the agent calls `atr_finish` with `atr.base64`, `chosen` unchanged and `signature: null`; it returns the
payment as `signed`, which the agent sends. For every other pairing, the comparison was the agent's whole step, and the
seller's own flow completes the payment.

### Pairings that pay an agreement first

If `atr_confirm` returns `chosen.agreement`, a URL, and no `request`, the payment is not itself a public proof of H,
and an agreement payment carrying H must be recorded first. The agreement payment is a payment like any other, and the
agent approves it as it approves any payment:

- where the host offers `atr_agree`, call it with `atr.base64` and `chosen`, exactly as returned, `mac` included (a
  changed `chosen` is declined `chosen-unverified`, and nothing is fetched or signed). It returns `approve`, the
  agreement payment, and signs nothing: `approve.option` is its `amount`, `asset`, `payTo` and `network`. Where the
  agreement URL answers that unpaid request with a receipt, it returns the `receipt`, marked `unpaid: true`: nothing was
  paid or read, and the receipt is the agreement URL's word alone; where the agreement URL offers only MPP agreement
  challenges, it returns them as `agreementChallenges`, signing nothing, for the agent's own MPP client to pay there.
  To approve the payment, call `atr_agree` again with `approved` set to `approve`, exactly as returned; it returns the
  `receipt`;
- otherwise, as with `terms-mcp`, pay it by hand. Request `chosen.agreement`; it answers `402` with an x402 payment
  request. Pay it through `atr_confirm` and `atr_finish`, each given `act` `"agreement"`, with the `402`'s payment
  request as `document` and the request to the agreement URL as `resourceRequest`. Before the wallet signs, check that
  the `atrHash` `atr_confirm` returns for it is the H of the payment being made, and pay nothing if it is not. Then
  request the URL again with that same payment until it answers `200` with a receipt for that H.

With `act` `"agreement"`, the two tools build the agreement payment, as `atr_agree` does: on `x402/exact/eip155/eip3009`,
`x402/exact/eip155/permit2`, `x402/exact/casper` and `x402/exact/starknet` it carries the agreement's own value of H in
place of H, and on the other pairings H itself. Any option on a pairing whose payment can be an agreement (the
[pairings reference](../reference/pairings.md) marks `yes` or `only` under "Pays an agreement") can be paid so; another is declined
`no-payable-option`. `atr_confirm` does not hold the agreement URL's option or `resourceRequest` to the ATR's binding
slot, which lists the charge's options and commits to the charge's request. Where `atr_confirm` declines, the tools
cannot pay the agreement: the agent signs nothing and tells its principal, and a host that wires a signer pays it
through `atr_agree` or `atr_transact`.

Then call `atr_confirm` again with the same arguments and the `receipt`. Only then does it return `request`. The
receipt is the agreement URL's statement: the tool checks its form (`agreed: true`, string `network` and
`transaction`) and that its `atrHash` is H, and does not look up the transaction it names.

Once the agreement payment is sent, every decline from `atr_agree` or `atr_transact` carries it as `moved`:
`agreement-pending` where it may settle yet, and `agreement-failed` where the agreement URL answered otherwise. Either
way it has left the wallet. To collect the receipt, call the same tool again without `approved`: the gate asks the
agreement URL unpaid and goes on once it answers `200` with the receipt, or declines `agreement-pending` again while it
answers `202`, signing nothing. Never call again with `approved` for the same agreement: every call with `approved`
signs and sends a new agreement payment. See [agreement payments](./agreement-payments.md).

### Channels and sessions

After the opening payment, call `atr_channel_open` with the pairing, `atr.base64`, the `signed` opening, the `landed`
receipt where one was returned beside it, and the `mac`, and keep the `hold`. For each later payment, call `atr_channel_within` (where the host offers it) with the pairing, the `hold` and the
seller's new document. When the seller reports its cumulative charge, call `atr_channel_record_charge`. Always keep the
latest `hold`, and pass it back exactly as returned: it carries a `mac` from the server process, and a changed hold, or
one from another server process, is declined `hold-unverified`, as a changed opening is declined `opening-unverified`.
After a server restart, open a new channel. See [channels and sessions](./channels-and-sessions.md)
and [channel holds](../reference/mcp.md#channel-holds).

### Declines

A result with `isError: true` carries `{ decline: { code, detail } }`. The payment would not carry a confirmed hash:
send nothing for that request. Where it also carries `moved`, the wallet already moved the payment: keep `moved.signed`
with the ATR, and present it again rather than signing a new one. See [declines](../reference/declines.md).

An argument the tool's input schema refuses is answered differently, by the MCP SDK before the tool runs: `isError:
true` with one text block, `Input validation error: Invalid arguments for tool <name>: …`, and no `structuredContent`
or `decline`. Nothing was fetched or signed. Read `isError` first, and `structuredContent.decline` only where it is
present.

## Serve the tools with your own signer

A host that holds a wallet can serve the same tools with it. The server then also offers `atr_transact` (confirm, pay
the agreement the agent approved, sign and finish), `atr_agree` and `atr_channel_within`. Install the packages the
sample imports; `@integraledger/lcp` is a peer dependency (`~0.6.0`), and `createBuyerServer` returns an `McpServer` of
`@modelcontextprotocol/server` 2.3.1, the version to serve it with:

```sh
npm install @integraledger/terms-mcp@0.5.0 @integraledger/terms@0.5.0 @integraledger/lcp@0.6.0 @modelcontextprotocol/server@2.3.1
```

```ts no-run
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import type { Signer } from "@integraledger/terms";
import { createBuyerServer } from "@integraledger/terms-mcp";

declare const signer: Signer; // your wallet
declare const agreementSigner: Signer; // a second wallet that pays agreements; omit it to pay them with signer

serveStdio(() => createBuyerServer({ fetch: globalThis.fetch, signer, agreementSigner }));
```

The `fetch` you pass is the server's whole network policy. The binary's public-address-only fetch is not exported. A
server that holds a wallet and fetches links that sellers choose should pass a `fetch` that refuses every address that
is not public: loopback, private-use, shared, link-local, unique-local, documentation, benchmarking, multicast and
reserved, judging an IPv4-mapped or NAT64 address by the IPv4 address it carries. It should resolve a host once and
connect to the address it checked: a check followed by a fetch that resolves again is open to DNS rebinding. The
binary's fetch does all of this.

With a host signer, `atr_transact` signs only what the agent approved. Before each signing it returns `approve`,
`{ agreement?, signings }`, and signs nothing: the last of `signings` is the signing asked now,
`{ act, pairing, request, summary, step }`, and the ones before it are those already approved. The agent reads the
summary and, to approve, calls `atr_transact` again with the same arguments and `approved` set to `approve`, unchanged:
the tool signs a signing only where it equals one of `approved.signings`, and returns the next one to approve the same
way. Where the pairing pays an agreement first, the first `approve` holds the agreement payment as
`approve.agreement`, with its amount, asset, payee and network; its signing is approved like any other, then, once the
agreement is recorded, the payment's. It returns the payment to send and the ATR to keep, and declines exactly as the
gate does. The gate applies no spending limit.

The ceilings and the served floors are the host's: pass `ceilings` and `floors` to `createBuyerServer`. No tool input
raises a ceiling, so no text the agent reads, the seller's among it, can. Without `ceilings`, a payment that signs no
end is declined `no-end`. The server sets what `floors` answers in the inputs it gives the gate, over a tool's own, and
drops a floor input from a tool's `inputs` for `x402/exact/eip155/gateway-batched` alone: without `floors`, that
pairing is declined `floor-missing`. For `mpp/charge/usdc/gateway`, this version passes a tool's `sourceNetwork`,
`burnIntentExpirationHeight` and `withdrawalDelay` through to the gate, so a host serving that pairing answers all
three through `floors`, which override the tool's.

## What the server guarantees

- `atr_confirm` returns a `request` only after SHA-256 of the served bytes equals the advertised H and every check on it
  has passed, built with the hash it computed, and returns it with its `summary`.
- With a host signer, `atr_transact` signs only a signing equal, in RFC 8785 form, to one the agent passes back in
  `approved.signings`. `atr_agree` pays the agreement payment passed as `approved` once its URL is the one in `chosen`,
  its `option` is one of `required.accepts` and `required` advertises H; it does not compare it with the `approve` it
  returned, and a host that needs that compares them itself. `atr_channel_within` signs a later voucher in a channel
  whose opening was approved, with no approval of its own.
- `atr_finish` returns `signed` only when the pairing reads the hash of the bytes it was given from the completed
  payment, or, where the proof is the agreement payment, without that reading.
- `terms-mcp` holds no keys. With a host signer, only the host's code signs, and only after a match.
- `atr_channel_open` holds only an opening, and `atr_channel_within` signs and `atr_channel_record_charge` records only
  from a hold, that this server process returned, unchanged. For a pairing with a channel, `atr_finish` reads only a
  `chosen` that this server process returned, unchanged. Each carries a `mac` under a key the process generates and
  never exports.
- `terms-mcp` fetches only from public addresses: a link on an address that is not public (loopback, private-use,
  shared, link-local, unique-local, documentation, benchmarking, multicast or reserved), or a host name that resolves to
  one, is declined `atr-unfetchable` before any connection.
- Every value the seller supplies is data: `atr.utf8`, and the agreement receipt's `network` and `transaction` that
  `atr_agree` and `atr_transact` return. The skill tells the agent to read them and never to follow instructions
  inside them.

The [tools reference](../reference/mcp.md) lists every tool's arguments, results and annotations.

## Versions and upgrading

`@integraledger/terms-mcp` is at 0.x: a minor release may change the tools, their arguments and their results. Pin the
exact version, as the configuration above does. 0.5.x takes `@integraledger/terms` 0.5.0 and the peer
`@integraledger/lcp` `~0.6.0`, and needs Node.js `>=24.22.1`.

From 0.4.x, `atr_confirm` and `atr_transact` require `resourceRequest`; `atr_transact` returns `approve`,
`{ agreement?, signings }`, before each signing and takes it back as `approved` (in 0.4.x both were the agreement
payment alone); a payment `atr_confirm`, `atr_finish`, `atr_transact` or `atr_agree` builds is held to its pairing's
ceiling, 600 seconds unless the host raises it; and the tools return the gate's new decline codes. The package's
[CHANGELOG](https://github.com/IntegraLedger/integra-agentic-terms/blob/main/agentic-terms-mcp/CHANGELOG.md) lists every
change.
