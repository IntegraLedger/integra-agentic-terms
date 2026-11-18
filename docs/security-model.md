---
title: Security model
description: What the buyer gate defends against, what it guarantees and how the code enforces each guarantee, what it trusts, and what it leaves to you.
---

The gate's purpose is narrow: the payment you sign carries the hash of the bytes you received, and what you sign is held
to what those bytes commit to and shown to you first. This page is for whoever decides whether an agent may pay through
the gate. It states the threat the gate answers, what it guarantees and how, what it trusts, and what it does not do.
The checks, their order and the decline each answers are fixed by the profile
[`buyer-gate.md`](https://github.com/IntegraLedger/integra-agentic-terms/blob/main/agentic-terms/profiles/buyer-gate.md),
for both languages alike.

## Threat model

The gate stands between the seller's offer and your signer. It assumes that the seller, or anyone who can change what
the seller's link serves, may:

- serve bytes other than the record H names, or bytes the two languages would read differently;
- offer, on x402 or MPP, an option other than those the record commits to, or answer a request other than yours;
- ask for a signature that grants more than its offer shows, or that stays payable for a long time;
- choose every URL the gate fetches: the ATR's link and the agreement URL are both the seller's.

The guarantees below answer the first three. The fourth is yours to answer, with the `fetch` you pass (see
[The network](#the-network)).

The gate trusts:

- your process, your `fetch`, your signer and your approver;
- in `finish` and `check`, the bytes, `chosen` and `landed` you hand back. `finish` recomputes H from the bytes and
  rebuilds the payment from `chosen`; neither function fetches anything again. Keep `chosen` and the bytes on your side
  of a process boundary, or seal them;
- the agreement URL's word that an agreement is recorded (see [What it does not do](#what-it-does-not-do)).

Out of scope: the record's terms, settlement and facilitators, the truth of the agreement receipt, and flaws in a
seller's server, a wallet or a chain.

## What the gate guarantees

| Guarantee | How |
| --- | --- |
| Nothing is signed before the comparison. | The signer is called only after SHA-256 of the served bytes equals the advertised H. On any decline before that point, the signer is never called. |
| The comparison is exact. | H is computed over the bytes as received, never over a re-serialised copy, and compared with the advertised value as 32 decoded bytes (so the hex's case does not matter, and a malformed value never matches). |
| Both languages read the ATR alike. | The gate parses the bytes it hashed, refusing exactly what the protocol package's `assemble` refuses in a party's bytes: not UTF-8, a byte-order mark, anything but one JSON text, nesting past 64 levels, a repeated member name, a number that rounds to infinity, and an integer outside ±(2^53 − 1). A text one language would read differently from the other is declined `atr-malformed`. |
| The option and the request are the ones the ATR commits to. | Where the ATR's binding slot lists the options offered (`accepts` in `x402`, `challenges` in `mpp`, `options` in `acp`, `ap2`, `card` and `ucp`, `paymentOptions` in `ack`), the option chosen, as its pairing's `unplaced` gives it, must equal one of them as RFC 8785 JSON; an MPP challenge must equal one of them by its bound members (the protocol package's `issuedDigest`, without `id` and the `opaque` members); and on `card`, whose documents do not show the seller's checkout id, a listed option must be of the pairing's `scheme` (`option-not-in-atr`). Where the `x402` slot holds a `request` commitment, the gate computes that commitment of `resourceRequest` and declines another (`request-mismatch`). No agreement option is compared: it is held by the approval alone. Neither comparison judges a term. |
| The payment carries the computed hash. | The build takes the hash the gate computed, not the string the seller advertised. |
| The hash is read back from the payment. | `finish` rebuilds the payment from `chosen` and the bytes, joins the signer's answer, and reads H back out of the completed payment through the pairing's binding. It returns the payment only when that value is the hash of the bytes, or, where the proof is the agreement payment, without that reading. |
| A payment without a public proof waits for its agreement. | For a pairing whose payment is not itself a public proof of H, `transact` and `atr_transact` call the signer only after the agreement URL answers `200` with a receipt naming that H. The gate checks the receipt's form and that its `atrHash` is H, and does not look up the transaction it names; a receipt answered to the first, unpaid request is the agreement URL's word alone, and the gate, having made no agreement payment and read none, returns it marked `unpaid: true`. `atr_confirm` returns no `request` before a receipt of that form, for that H, is passed to it. `confirm` and `finish` neither pay nor check the agreement: a caller that drives them signs `request` only with the receipt `agree` returns. terms sends no MPP credential to an agreement URL: where it offers only MPP agreement challenges, the gate returns them, signing nothing, for the caller's own MPP client to pay, and pays the charge only once a later call finds the agreement recorded. |
| `transact` shows every payment before it is signed. | `transact` (and over MCP, `atr_transact`) asks the caller's approver about each signing, the agreement payment's and each later step's among them, once every check on it has passed and before the signer is called, with its summary: every authority the signature grants, computed from the request handed to the signer, never from the seller's option. The signer is called only on `true`; any other answer, a throw or a rejection declines `not-approved`. A request the gate cannot summarize is declined `summary-missing`. Where the pairing's payment needs its agreement first, the agreement payment is also returned to the buyer's agent, with its amount, asset, payee and network, before it is paid; where the seller's first response offers the agreement alone, `transact` pays the agreement option that serves the charge as soon as the approver approves it, without returning it first. This holds of `transact` alone: it does not hold of a payment a caller signs itself from `confirm` and `finish`, which return the request with its summary for the caller to show, nor of `agree` and `within`, which take no approver: `agree` holds the agreement payment to its summary and its ceiling all the same, and `within` computes no summary. The gate applies no spending limit: what to approve is the approver's decision. |
| Through `transact`, `confirm`, `finish` and `agree`, a signed payment's window is bounded. | A payment that would stay payable longer than its pairing's ceiling is declined before it is signed (`past-ceiling`), and a form that signs no end is declined (`no-end`), unless the caller raises that pairing's ceiling. Where the wallet picks the expiry itself, it is handed the latest deadline it may sign, and the deadline it signed is read back before the payment is returned. On a rail whose service serves a floor, the caller gives that floor in `inputs` (`floor-missing` otherwise), and the ceiling is the floor plus the service's margin. `agree`, called on its own, holds the agreement payment to its pairing's ceiling as `transact` does, `ceilings` raising it. `within` holds the voucher it signs to no ceiling: a voucher stays payable as long as its channel. |
| The fetch is bounded. | One `GET` of an `https` link, with no redirect, one 10-second deadline over headers and body, and at most 1 MiB read. A declared or streamed length over the bound cancels the body. |
| The bytes hashed are the bytes sent. | Every request asks for `Accept-Encoding: identity`, and a `200` whose `Content-Encoding` names any coding (gzip, br, a stacked list) is declined with its body unread. Nothing is decompressed, so the bounds apply to the bytes on the wire. The agreement receipt is read the same way, at most 64 KiB. |
| A channel pays under its ATR. | `within` takes the ATR's bytes, H and the channel from the hold, and only the amount from the seller's new challenge. An x402 challenge must advertise the held H. An MPP session challenge that names another channel or another H is declined, and one with no legal context is signed under the held H. A recorded charge cannot exceed what was signed. |
| The gate holds nothing that signs. | It hands requests to your signer and never sees a key. |
| Your network policy applies. | Every request goes through the `fetch` (or `httpx.AsyncClient`) you pass. The library applies no address policy of its own: the `fetch` you pass is the only network policy. |

The TypeScript and Python gates enforce the same rules, and the shared [vectors](./reference/vectors.md) fix each one.

## The network

The seller chooses the URLs the gate fetches: the ATR's link, and, for a pairing paid after its agreement, the
agreement URL. The gate requires `https` and nothing else of the address, so a link may name a loopback, private-use or
link-local host, and the gate sends one `GET` there through the `fetch` you pass. Node's global `fetch` and a default
`httpx.AsyncClient` reach any address your process can.

Where your process can reach hosts a seller should not (a cloud metadata endpoint, an internal service), pass a `fetch`
that refuses loopback, private-use, link-local and unique-local addresses, and that resolves a host name once and
connects only to the address it checked, as the `terms-mcp` binary's fetch does (see
[the MCP tools](#the-mcp-tools-and-the-skill)).

## What it does not do

- **It does not judge the ATR.** The gate parses the record and reads only its binding slot's options and, on x402,
  its request commitment; it judges none of its terms. Whether the terms are acceptable is for you and your
  principal to decide.
- **It does not hold a card, ACP, AP2, UCP or ACK option to the ATR**, nor an agreement option, nor an MPP request to
  any commitment. Your approver is shown what each signs.
- **It does not check the payment's values.** Amount, payee, asset, timing and payer are not compared with the ATR. The
  gate shows them to your approver; a discrepancy is between the parties, and the ATR is the record of what was agreed.
- **It does not authenticate the agreement's receipt.** The receipt is the agreement URL's statement. The public proof
  is the transaction it names, on its network: look it up yourself where you rely on it.
- **It carries no business or legal logic.**
- **It does not store the ATR.** It returns the bytes; keeping them is yours. See
  [keeping the record](./guides/keeping-the-record.md).
- **It does not settle.** It returns the payment to you, except the agreement payment your approver approved, which it
  sends to the agreement URL. It never talks to a facilitator.

## What each payment proves

Pairings differ in where H sits. At coverage `full`, the buyer's own signed payment binds all of H, and a public ledger
records it when the payment settles. At coverage `none`, H rides in the seller's challenge, beside the payment, or not
in it at all, and the agreement payment is the public proof. Each pairing's registry data in the protocol package
states exactly what its payment shows and what it does not; the [pairings reference](./reference/pairings.md) quotes
every statement.

## The MCP tools and the skill

- The `terms-mcp` binary has no signer. The agent's own wallet signs the requests the tools return, each returned with
  its `summary`.
- With a host signer, `atr_transact` signs only a signing equal, in RFC 8785 form, to one the agent passes back in
  `approved.signings`. `atr_agree` pays the agreement payment passed as `approved` once its URL is the one in `chosen`,
  its `option` is one of `required.accepts` and `required` advertises H, with no summary or ceiling of its own; it does
  not compare it with the `approve` it showed, so a host that needs that compares them itself. `atr_channel_within`
  signs a later voucher in a channel whose opening was approved, with no approval of its own.
- The ceilings and the served floors are the host's (`createBuyerServer`'s `ceilings` and `floors`), never a tool
  input. No tool input raises a ceiling or names a floor: the server removes from a tool's `inputs` every floor input
  the gate's `FLOOR_INPUTS` names for the pairing, those of `x402/exact/eip155/gateway-batched` and
  `mpp/charge/usdc/gateway` alike.
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
- `atr_confirm` takes the agreement receipt the agent passes, and checks its form and that its `atrHash` is H, as the
  gate checks the agreement URL's.
- Every value the seller supplies is data: `atr.utf8`, and the agreement receipt's `network` and `transaction` that
  `atr_agree` and `atr_transact` return. The skill tells the agent to read them and never to follow instructions inside
  them.
- A discovery listing, or a hash an agent computes itself, is not a confirmation. The confirmation is `atr_finish`'s:
  it returns `signed` only when the pairing reads the hash from the completed payment, or, where the proof is the
  agreement payment, without that reading.

## Reporting a vulnerability

Report it privately through GitHub's private vulnerability reporting on the repository. See
[SECURITY.md](https://github.com/IntegraLedger/integra-agentic-terms/blob/main/SECURITY.md).
