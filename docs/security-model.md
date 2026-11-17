---
title: Security model
description: What the buyer gate guarantees, how each guarantee is enforced in the code, and what it leaves to you.
---

The gate's purpose is narrow: the payment you sign carries the hash of the bytes you received, and what you sign is held
to what those bytes commit to and shown to you first. This page states what it guarantees, how, and what it does not
do. The checks, their order and the decline each answers are fixed by the profile
[`buyer-gate.md`](https://github.com/IntegraLedger/integra-agentic-terms/blob/main/agentic-terms/profiles/buyer-gate.md),
for both languages alike.

## What the gate guarantees

| Guarantee | How |
| --- | --- |
| Nothing is signed before the comparison. | The signer is called only after SHA-256 of the served bytes equals the advertised H. On any decline before that point, the signer is never called. |
| The comparison is exact. | H is computed over the bytes as received, never over a re-serialised copy, and compared with the advertised value as 32 decoded bytes (so the hex's case does not matter, and a malformed value never matches). |
| Both languages read the ATR alike. | The gate parses the bytes it hashed, refusing exactly what the protocol package's `assemble` refuses in a party's bytes: not UTF-8, a byte-order mark, anything but one JSON text, nesting past 64 levels, a repeated member name, a number that rounds to infinity, and an integer outside ±(2^53 − 1). A text one language would read differently from the other is declined `atr-malformed`. |
| The option and the request are the ones the ATR commits to. | Where the ATR's binding slot lists the options offered, the option chosen must equal one of them as RFC 8785 JSON (`option-not-in-atr`). Where it holds a commitment to the buyer's request, the gate computes that commitment of `resourceRequest` and declines another (`request-mismatch`). Neither comparison judges a term. |
| The payment carries the computed hash. | The build takes the hash the gate computed, not the string the seller advertised. |
| The hash is read back from the payment. | `finish` rebuilds the payment from `chosen` and the bytes, joins the signer's answer, and reads H back out of the completed payment through the pairing's binding. It returns the payment only when that value is the hash of the bytes, or, where the proof is the agreement payment, without that reading. |
| A payment without a public proof waits for its agreement. | For a pairing whose payment is not itself a public proof of H, `transact` and `atr_transact` call the signer only after the agreement URL answers with a receipt for that H, and `atr_confirm` returns no `request` before that receipt is passed to it. `confirm` and `finish` neither pay nor check the agreement: a caller that drives them signs `request` only with the receipt `agree` returns. terms sends no MPP credential to an agreement URL: where it offers only MPP agreement challenges, the gate returns them, signing nothing, for the caller's own MPP client to pay, and pays the charge only once a later call finds the agreement recorded. |
| `transact` shows every payment before it is signed. | `transact` (and over MCP, `atr_transact`) asks the caller's approver about each signing, the agreement payment's and each later step's among them, once every check on it has passed and before the signer is called, with its summary: every authority the signature grants, computed from the request handed to the signer, never from the seller's option. The signer is called only on `true`; any other answer, a throw or a rejection declines `not-approved`. A request the gate cannot summarize is declined `summary-missing`. The agreement payment is also returned to the buyer's agent with its amount, asset, payee and network before it is paid. This holds of `transact` alone: it does not hold of a payment a caller signs itself from `confirm` and `finish`, which return the request with its summary for the caller to show, nor of `agree` and `within`, which take no approver. The gate applies no spending limit: what to approve is the approver's decision. |
| A signed payment's window is bounded. | A payment that would stay payable longer than its pairing's ceiling is declined before it is signed (`past-ceiling`), and a form that signs no end is declined (`no-end`), unless the caller raises that pairing's ceiling. Where the wallet picks the expiry itself, it is handed the latest deadline it may sign, and the deadline it signed is read back before the payment is returned. On a rail whose service serves a floor, the caller gives that floor in `inputs` (`floor-missing` otherwise), and the ceiling is the floor plus the service's margin. |
| The fetch is bounded. | One `GET` of an `https` link, with no redirect, one 10-second deadline over headers and body, and at most 1 MiB read. A declared or streamed length over the bound cancels the body. |
| The bytes hashed are the bytes sent. | Every request asks for `Accept-Encoding: identity`, and a `200` whose `Content-Encoding` names any coding (gzip, br, a stacked list) is declined with its body unread. Nothing is decompressed, so the bounds apply to the bytes on the wire. The agreement receipt is read the same way, at most 64 KiB. |
| A channel pays under its ATR. | `within` takes the ATR's bytes, H and the channel from the hold, and only the amount from the seller's new challenge. An x402 challenge must advertise the held H. An MPP session challenge that names another channel or another H is declined, and one with no legal context is signed under the held H. A recorded charge cannot exceed what was signed. |
| The gate holds nothing that signs. | It hands requests to your signer and never sees a key. |
| Your network policy applies. | Every request goes through the `fetch` (or `httpx.AsyncClient`) you pass. |

The TypeScript and Python gates enforce the same rules, and the shared [vectors](./reference/vectors.md) fix each one.

## What it does not do

- **It does not judge the ATR.** The gate parses the record and reads only its binding slot's options and request
  commitment; it judges none of its terms. Whether the terms are acceptable is for you and your principal to decide.
- **It does not check the payment's values.** Amount, payee, asset, timing and payer are not compared with the ATR. The
  gate shows them to your approver; a discrepancy is between the parties, and the ATR is the record of what was agreed.
- **It carries no business or legal logic.**
- **It does not store the ATR.** It returns the bytes; keeping them is yours. See
  [keeping the record](./guides/keeping-the-record.md).
- **It does not settle.** It returns the payment to you. It never talks to a facilitator.

## What each payment proves

Pairings differ in where H sits. At coverage `full`, the buyer's own signed payment binds all of H, and a public ledger
records it when the payment settles. At coverage `none`, H rides in the seller's challenge, beside the payment, or not
in it at all, and the agreement payment is the public proof. Each pairing's registry data in the protocol package
states exactly what its payment shows and what it does not; the [pairings reference](./reference/pairings.md) quotes
every statement.

## The MCP tools and the skill

- The `terms-mcp` binary has no signer. The agent's own wallet signs the requests the tools return, each returned with
  its `summary`.
- With a host signer, `atr_transact` and `atr_agree` sign only a signing the agent was shown and approved, unchanged;
  `atr_channel_within` signs a later voucher in a channel whose opening was approved, with no approval of its own. The
  ceilings and the served floors are the host's, never a tool input, so no text the agent reads raises a ceiling or
  names a floor.
- A channel opening and a channel hold the tools return carry a `mac` under a key of the server process.
  `atr_channel_open` declines any other opening, `opening-unverified`, and `atr_channel_within` and
  `atr_channel_record_charge` decline any other hold, `hold-unverified`, before the gate is called.
- The `chosen` that `atr_confirm` returns carries a `mac` under the same key. `atr_agree` pays only the agreement URL in
  a `chosen` whose `mac` verifies, and declines any other `chosen`, `chosen-unverified`, before anything is fetched or
  signed. For a pairing with a channel, `atr_finish` reads only a `chosen` whose `mac` verifies, and declines any
  other, `chosen-unverified`, before the gate is called.
- The `terms-mcp` binary fetches only from public addresses. A link that names a loopback, private-use, shared,
  link-local, unique-local, documentation, multicast or reserved address is refused before any connection, and a host
  name is resolved once and connected to only when every address it resolves to is public. A host that serves the tools
  with `createBuyerServer` applies its own network policy through the `fetch` it passes.
- Every value the seller supplies is data: `atr.utf8`, and the agreement receipt's `network` and `transaction` that
  `atr_agree` and `atr_transact` return. The skill tells the agent to read them and never to follow instructions inside
  them.
- A discovery listing, or a hash an agent computes itself, is not a confirmation. The confirmation is `atr_finish`'s:
  it returns `signed` only when the pairing reads the hash from the completed payment, or, where the proof is the
  agreement payment, without that reading.

## Reporting a vulnerability

Report it privately through GitHub's private vulnerability reporting on the repository. See
[SECURITY.md](https://github.com/IntegraLedger/integra-agentic-terms/blob/main/SECURITY.md).
