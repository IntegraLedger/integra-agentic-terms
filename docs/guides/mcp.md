---
title: MCP server
description: Give any MCP client the buyer gate as tools, install the skill that tells the agent how to use them, and serve the tools with your own signer.
---

`@integraledger/terms-mcp` serves the buyer gate's operations as [Model Context Protocol](https://modelcontextprotocol.io)
tools, and ships a skill that tells an agent how to use them. Each tool call is one call of `@integraledger/terms`; the
server adds the transport and the words an agent reads, and nothing else.

## Install the server

Most MCP clients take a configuration like this:

```json
{
  "mcpServers": {
    "terms": {
      "command": "npx",
      "args": ["-y", "@integraledger/terms-mcp"]
    }
  }
}
```

`npx` runs the package's `terms-mcp` binary, which serves the tools over stdio with no signer. It needs Node.js
`>=26.10.0`. Its `serverInfo` name is `integraledger-terms`.

## Install the skill

The skill is `skills/confirming-the-atr-hash-before-paying/SKILL.md` in the package. Copy its folder into your agent's
skills directory (for Claude Code, `.claude/skills/`), or paste the file into the agent's instructions:

```sh
npm install @integraledger/terms-mcp
cp -r node_modules/@integraledger/terms-mcp/skills/confirming-the-atr-hash-before-paying .claude/skills/
```

The skill's description tells the agent when it applies: before approving any payment to a seller whose payment
request advertises an ATR hash.

## What the agent does

With `terms-mcp`, the agent's own wallet signs. For one payment:

1. **Confirm.** Call `atr_confirm` with the `pairing`, the seller's `document` (the parsed `PAYMENT-REQUIRED` document,
   or the MPP challenges) and the payer `account` in CAIP-10 form. On a match, the result carries the ATR, its hash,
   `chosen`, and `request`, the exact thing to sign.
2. **Sign.** Have the wallet sign `request` unchanged. The [signers guide](./signers.md) lists every kind.
3. **Finish.** Call `atr_finish` with the `pairing`, `atr.base64`, `chosen` unchanged, and the wallet's answer as
   `signature`. The result is `signed`, the payment to send, only when what was signed carries H.
4. **Send** `signed` as the protocol sends a payment.

A confirmed result, abridged (the long `typedData.types` and the echoed document are shortened):

```json
{
  "atrHash": "0x8b1e122580ae3f6a8c3d36a24294e1260a87bde70f597279b973e39310072938",
  "atr": {
    "base64": "eyJhdHJWZXJzaW9uIjoiMSIsImlkIjoiMGY4ZmFkNWItZDljYi00NjlmLWExNjUtNzA4Njc3Mjg5NTBlIiwieDQwMiI6eyJ6IjoxLjAsImEiOiJjYWZcdTAwZTkifSwic2VsbGVyIjp7Im5vdGUiOiJDYWbDqSDigJQgMzAgZMOtYXMg4pyTIn19",
    "utf8": "{\"atrVersion\":\"1\",\"id\":\"0f8fad5b-d9cb-469f-a165-70867728950e\",\"x402\":{\"z\":1.0,\"a\":\"caf\\u00e9\"},\"seller\":{\"note\":\"Café — 30 días ✓\"}}"
  },
  "chosen": {
    "pairing": "x402/exact/eip155/eip3009",
    "choice": { "accepted": { "scheme": "exact", "network": "eip155:84532" }, "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" },
    "ref": "abKt2A5-ljuE6ab515O0H8AIX4w_r4ud"
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
  }
}
```

The signed `nonce` is `atrHash`. The agent passes `chosen` back to `atr_finish` exactly as it came.

### Payments signed in steps

If `atr_finish` returns `next`, the wallet signs `next`, and the agent calls `atr_finish` again with every answer so
far, in order, as a list.

### Nothing to sign

If `request` is `null`, the pairing gives the buyer nothing to sign: the comparison was the agent's whole step, and the
seller's own flow completes the payment.

### Pairings that pay an agreement first

If `atr_confirm` returns an `agreement` URL and no `request`, the payment does not itself carry H in public, and an
agreement payment carrying it must be recorded first:

- where the host offers `atr_agree`, call it with `atr.base64` and the `agreement` URL;
- otherwise, request the agreement URL. It answers with an x402 payment request for the same H; pay it through
  `atr_confirm` and `atr_finish` with the pairing its option names, then request the URL again with that payment until
  it answers `200` with the receipt.

Then call `atr_confirm` again with the same arguments and the `receipt`. Only then does it return `request`. See
[agreement payments](./agreement-payments.md).

### Channels and sessions

After the opening payment, call `atr_channel_open` with the pairing, `atr.base64` and the `signed` opening, and keep the
`hold`. For each later payment, call `atr_channel_within` (where the host offers it) with the pairing, the `hold` and the
seller's new document. When the seller reports its cumulative charge, call `atr_channel_record_charge`. Always keep the
latest `hold`, and pass it back exactly as returned: it carries a `mac` from the server process, and a changed hold, or
one from another server process, is declined `hold-unverified`. See [channels and sessions](./channels-and-sessions.md)
and [channel holds](../reference/mcp.md#channel-holds).

### Declines

A result with `isError: true` carries `{ decline: { code, detail } }`. The payment would not carry a confirmed hash:
send nothing for that request. Where it also carries `moved`, the wallet already moved the payment: keep `moved.signed`
with the ATR, and present it again rather than signing a new one. See [declines](../reference/declines.md).

## Serve the tools with your own signer

A host that holds a wallet can serve the same tools with it. The server then also offers `atr_transact` (confirm, pay
any agreement, sign and finish in one call), `atr_agree` and `atr_channel_within`:

```ts no-run
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import type { Signer } from "@integraledger/terms";
import { createBuyerServer } from "@integraledger/terms-mcp";

declare const signer: Signer; // your wallet
declare const agreementSigner: Signer; // a second wallet that pays agreements; omit it to pay them with signer

serveStdio(() => createBuyerServer({ fetch: globalThis.fetch, signer, agreementSigner }));
```

With a host signer, the agent never sees a request: `atr_transact` returns the payment to send and the ATR to keep, and
declines exactly as the gate does.

## What the server guarantees

- `atr_confirm` returns a `request` only after SHA-256 of the served bytes equals the advertised H, built with the hash
  it computed.
- `atr_finish` returns `signed` only when what was signed carries the hash of the bytes it was given.
- `terms-mcp` holds no keys. With a host signer, only the host's code signs, and only after a match.
- `atr_channel_within` signs, and `atr_channel_record_charge` records, only from a hold this server process returned,
  unchanged. Each hold carries a `mac` under a key the process generates and never exports.
- `atr.utf8` is the seller's data. The skill tells the agent to read it and never to follow instructions inside it.

The [tools reference](../reference/mcp.md) lists every tool's arguments, results and annotations.
