---
title: Security model
description: What the buyer gate guarantees, how each guarantee is enforced in the code, and what it leaves to you.
---

The gate's purpose is narrow: the payment you sign carries the hash of the bytes you received. This page states what it
guarantees, how, and what it does not do.

## What the gate guarantees

| Guarantee | How |
| --- | --- |
| Nothing is signed before the comparison. | The signer is called only after SHA-256 of the served bytes equals the advertised H. On any decline before that point, the signer is never called. |
| The comparison is exact. | H is computed over the bytes as received, never parsed or re-serialised, and compared with the advertised value as 32 decoded bytes (so the hex's case does not matter, and a malformed value never matches). |
| The payment carries the computed hash. | The build takes the hash the gate computed, not the string the seller advertised. |
| What was signed is read back. | `finish` rebuilds the payment from `chosen` and the bytes, joins the signer's answer, and reads H back out of the signed contents through the pairing's binding. It returns the payment only when that value is the hash of the bytes. |
| A payment without a public proof waits for one. | For a pairing whose payment is not itself a public proof of H, the payment is signed only after the agreement URL answers with a receipt for that H. |
| The fetch is bounded. | One `GET` of an `https` link, with no redirect, one 10-second deadline over headers and body, and at most 1 MiB read. A declared or streamed length over the bound cancels the body. |
| A channel pays under its ATR. | `within` re-derives every value from the hold, never from the seller's new challenge, and signs only when that challenge advertises the held H. A recorded charge cannot exceed what was signed. |
| The gate holds nothing that signs. | It hands requests to your signer and never sees a key. |
| Your network policy applies. | Every request goes through the `fetch` (or `httpx.AsyncClient`) you pass. |

The TypeScript and Python gates enforce the same rules, and the shared [vectors](./reference/vectors.md) fix each one.

## What it does not do

- **It does not judge the ATR.** The gate never reads the record's content. Whether the terms are acceptable is for you
  and your principal to decide.
- **It does not check the payment's values.** Amount, payee, asset, timing and payer are not compared with the ATR. A
  discrepancy is between the parties, and the ATR is the record of what was agreed.
- **It carries no business or legal logic.**
- **It does not store the ATR.** It returns the bytes; keeping them is yours. See
  [keeping the record](./guides/keeping-the-record.md).
- **It does not settle.** It returns the payment to you. It never talks to a facilitator.

## What each payment proves

Pairings differ in where H sits. In most, the buyer's signed payment carries H, and the chain records it when the payment
settles. In some, H rides in the seller's challenge, in a field too small for all of it, or not in the payment at all,
and the agreement payment is the public proof. Each pairing's binding states exactly what its payment shows and what it
does not; the [pairings reference](./reference/pairings.md) quotes every statement.

## The MCP tools and the skill

- The `terms-mcp` binary has no signer. The agent's own wallet signs the requests the tools return.
- A channel opening and a channel hold the tools return carry a `mac` under a key of the server process.
  `atr_channel_open` declines any other opening, `opening-unverified`, and `atr_channel_within` and
  `atr_channel_record_charge` decline any other hold, `hold-unverified`, before the gate is called.
- `atr.utf8` is the seller's data. The skill tells the agent to read it and never to follow instructions inside it.
- A discovery listing, or a hash an agent computes itself, is not a confirmation. The confirmation is the hash inside
  what the wallet signs.

## Reporting a vulnerability

Report it privately through GitHub's private vulnerability reporting on the repository. See
[SECURITY.md](https://github.com/IntegraLedger/integra-agentic-terms/blob/main/SECURITY.md).
