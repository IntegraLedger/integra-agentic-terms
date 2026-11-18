---
title: Introduction
description: The buyer gate confirms that the record a seller serves hashes to the value a payment will carry, before an agent's wallet signs anything.
---

An agent that pays a seller should know what it is agreeing to. Under the Legal Context Protocol (LCP), the seller
publishes the agreement's record, an **Agentic Transaction Record (ATR)**, and advertises its SHA-256, the
**ATR hash (H)**, beside the payment request. Where the payment the agent approves carries H, that approval is the
buyer's acceptance of that exact record; where it does not, the pairing's statement of what it proves says so.

The packages documented here are the buyer's side of that pattern. Their centre is the **buyer gate**, which, before your
wallet signs anything:

1. fetches the ATR from the seller's `https` link, once and within bounds;
2. computes SHA-256 over the exact bytes it received and compares it with H;
3. parses those bytes and holds the option you pay (and on x402 the request you make) to what the ATR's binding slot
   commits to;
4. builds the payment with that hash, shows your approver what the signature grants, and declines a payment that would
   stay payable past its ceiling;
5. only on your approver's `true`, hands the request to your signer;
6. reads H back from the completed payment, and returns the payment only if it is the hash of those bytes, or, where the
   proof is the agreement payment, without that reading.

It works across x402, MPP, Spend Permissions, card, AP2, UCP, ACP and ACK payments, on EVM chains, Tempo, Solana, Stellar, the XRP Ledger,
Hedera, Algorand, Aptos, Sui, NEAR, Starknet, Polkadot, TRON, TON, Cardano, Casper, Concordium, Stacks and Lightning.
It holds no keys, judges none of the record's terms, and carries no business or legal logic. The checks and their
declines are fixed, for both languages, by the profile
[`buyer-gate.md`](https://github.com/IntegraLedger/integra-agentic-terms/blob/main/agentic-terms/profiles/buyer-gate.md).

## The packages

| Package | For | Install |
| --- | --- | --- |
| `@integraledger/terms` | TypeScript agents | `npm install @integraledger/terms@0.5.1 @integraledger/lcp@0.6.1` |
| `@integraledger/terms-mcp` | Any agent with an MCP client: the gate as tools, and a skill | `npx -y @integraledger/terms-mcp@0.5.1` |
| `integraledger-terms` | Python agents | `pip install integraledger-terms==0.5.1` |

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
- [Security model](./security-model.md): what the gate defends against, what it trusts, and what it leaves to you.
- [Upgrading](./upgrading.md): what 0.x means, and each call to change from 0.4.x.

## For AI agents

The site publishes [`llms.txt`](https://agenticterms.integraledger.com/llms.txt), an index of every page with the
versions it documents, and [`llms-full.txt`](https://agenticterms.integraledger.com/llms-full.txt), every page in one
file, with one file for each section: [guides](https://agenticterms.integraledger.com/guides/llms-full.txt),
[reference](https://agenticterms.integraledger.com/reference/llms-full.txt) and
[API](https://agenticterms.integraledger.com/api/llms-full.txt). Each page is also Markdown at its address with `.md`
added, such as [`/getting-started.md`](https://agenticterms.integraledger.com/getting-started.md), or at its own address
for a request whose `Accept` header prefers `text/markdown`. The protocol package the gate builds on is documented the
same way at [lcp.integraledger.com/llms.txt](https://lcp.integraledger.com/llms.txt).
