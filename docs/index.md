---
title: Introduction
description: The buyer gate confirms that the record a seller serves hashes to the value a payment will carry, before an agent's wallet signs anything.
---

An agent that pays a seller should know what it is agreeing to. Under the Legal Context Protocol (LCP), the seller
publishes the agreement's record, an **Agentic Transaction Record (ATR)**, and advertises its SHA-256, the
**ATR hash (H)**, beside the payment request. The payment the agent approves carries H, so paying is agreeing to that
exact record.

The packages documented here are the buyer's side of that pattern. Their centre is the **buyer gate**, which, before your
wallet signs anything:

1. fetches the ATR from the seller's `https` link, once and within bounds;
2. computes SHA-256 over the exact bytes it received and compares it with H;
3. only on a match, builds the payment with that hash and hands it to your signer;
4. reads H back out of what your signer signed, and returns the payment only if it is still the hash of those bytes.

It works across x402, MPP, card, AP2, UCP, ACP and ACK payments, on EVM chains, Tempo, Solana, Stellar, the XRP Ledger,
Hedera, Algorand, Aptos, Sui, NEAR, Starknet, Polkadot, TRON, TON, Cardano, Casper, Concordium, Stacks and Lightning.
It holds no keys, reads none of the record's content, and carries no business or legal logic.

## The packages

| Package | For | Install |
| --- | --- | --- |
| `@integraledger/terms` | TypeScript agents | `npm install @integraledger/terms @integraledger/lcp` |
| `@integraledger/terms-mcp` | Any agent with an MCP client: the gate as tools, and a skill | `npx -y @integraledger/terms-mcp` |
| `integraledger-terms` | Python agents | `pip install integraledger-terms` |

The TypeScript and Python gates are two implementations of the same rules. They run the same shared vectors and build
the same payments.

## Where to start

- [Getting started](./getting-started.md): a payment in TypeScript and in Python, and the gate refusing a record that
  changed by one byte.
- [Concepts](./concepts.md): the record, the hash, pairings, bindings, and what the gate does not do.
- [Pay with the gate](./guides/pay-with-the-gate.md): `transact`, and `confirm` then `finish` for a signer that lives
  elsewhere.
- [MCP server](./guides/mcp.md): give an agent the gate as tools.
- [Pairings](./reference/pairings.md): every protocol and rail the gate pays, and what each payment proves.
