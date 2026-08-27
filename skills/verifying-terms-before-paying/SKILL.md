---
name: verifying-terms-before-paying
description: Use when about to pay a seller that advertises terms — an HTTP 402 or x402 challenge, an ACP, AP2 or MPP checkout, a /.well-known/legal-context.json — and especially when the seller declares no terms fingerprint at all, or declares one over a document you cannot read.
---

# Verifying terms before paying

A seller can publish terms and *commit* to them, by advertising a fingerprint over the exact bytes. You
recompute that fingerprint over the bytes you were actually served. If they disagree, the document you read
is not the document the seller committed to.

Reading the terms is not verifying them. **Only a fingerprint the SELLER advertised binds the seller.**

## The tool

`@integraledger/lcp-mcp-server` exposes `lcp_verify_before_pay`. Give it the service origin; it fetches the
discovery document and the terms it points at, recomputes the fingerprint, and answers:

| verdict | means | `wouldHalt` |
|---|---|---|
| `verified` | served terms hash to the advertised fingerprint | false |
| `mismatch` | they do not — the document was changed, swapped or stale | **true** |
| `unverifiable` | nothing was committed, or the terms are not machine-readable | **true** |

Run it with `npx -y @integraledger/lcp-mcp-server` (read-only; every tool declares `readOnlyHint`). It never signs, never pays and
never holds a key.

## ⛔ No fingerprint is not a pass

**This is the one that gets missed.** When a seller advertises terms with no fingerprint, the honest
reading is not "nothing to check, proceed" — it is **nothing is committed**. The terms sit at a mutable URL,
the seller can serve you one document and someone else another, and can change it after you pay. There is
no artifact that binds the seller to what you read.

**A fingerprint you compute yourself does not fix this.** Hashing the bytes you were served records what
*you* saw. It is not a commitment, because the seller never made one — nothing binds them to those bytes,
and in a dispute it proves only that you hashed something. Storing it may be worth doing for your own
records. It is not verification and must not be counted as any part of one.

Paying here can be correct. What must not happen is paying while believing the terms were verified. That is
a decision your own policy makes explicitly — `@integraledger/agentic-terms` takes a stated `requiredLevel`
and a stated disposition for gaps — never a green light read out of a check that verified nothing.

| Rationalization | Reality |
|---|---|
| "It's only $49 — binding is disproportionate here" | The amount bounds your loss, not whether you know what you agreed to. Cheap purchases are where unread auto-renewals live. |
| "I'll hash it myself and store that" | Records what you saw. Binds the seller to nothing. Not verification. |
| "The vendor is legitimate and it's served over TLS" | TLS authenticates the channel at fetch time. It says nothing about what the document says tomorrow. |
| "The terms read fine — nothing unusual in them" | You read *a* document. Without a commitment there is nothing establishing it is the one governing your payment. |
| "I'll close the evidentiary gap myself" | The gap is the seller's missing commitment. You cannot close it from your side. |

**Red flags — stop and say "unverified" rather than "verified":**

- you computed the only hash in the transaction
- the words "low-stakes", "routine" or "proportionate" are load-bearing in your reasoning
- you are describing what you would do *instead of* verification as though it were verification

## What the check covers that a hand-rolled one does not

- **Terms you cannot read are `unverifiable`, even when the fingerprint matches.** A matching hash proves
  the bytes are authentic, not that their content is acceptable. A PDF you cannot parse is refused rather
  than passed through.
- **A non-conformant discovery document fails loudly** rather than having fields read off whatever JSON
  came back.
- **There is no seller signature to look for.** `legal-context.json` carries none at any level; a verifier
  that hunts for one is reading a field the protocol does not define.

## Out of scope

Whether the price is good, which offer to take, whether to negotiate, and whether to buy at all. This
answers one question — *are these the terms the seller committed to* — and nothing about how you trade.
