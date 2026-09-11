---
"@integraledger/agentic-terms": minor
---

The `PAYMENT-SIGNATURE` envelope, and the buyer's other half

`decodeX402Challenge`, `x402AcceptedEntry` and `x402PaymentHeader` ship the join that was never public.

⭐ **The sentence this closes on is not the one the gap was filed under.** It was filed as *"no **stock**
x402 client can pay a seller serving Legal Context Protocol terms."* What ships here makes such a seller
payable by **a stock x402 client plus one public Integra package** — a materially different sentence, and
the one that should stand.

The payment half was already public and needed nothing new: `@integraledger/lcp-binding-evm-x402` builds
the EIP-3009 authorization with `nonce = atrHash`, Apache-2.0 on npm, resolving anonymously. What was never
public is the ENVELOPE. So after this, the remaining distance between a stock client and such a seller is
**one `npm install`**, not a protocol difference. True zero-install interoperability is not what this buys
and no packaging choice would have bought it — that would be an x402 specification change.

**The shape is the guarantee.** The challenge is a REQUIRED argument and the `accepted` entry is derived
from it here, so a caller cannot build a payment without having been served an offer. x402 §6.1 says a
payment answers ONE offer; buyers that assembled the entry from a local template presented payments
answering an offer nobody had made, and it settled for as long as the seller compared it to nothing. The
entry is copied off the 402 this buyer was served, so a field the seller adds is echoed from the moment it
is added and there is no local constant to go stale.

⚠️ **It becomes a supported public API on the buyer side** — a shape that cannot change without a
deprecation, on the counterparty's side of the boundary. That cost is accepted deliberately.

Base64 goes through `TextEncoder`/`TextDecoder` rather than `Buffer`, so it runs unchanged on every runtime
this package supports. A bare `atob` yields latin-1 code units, and a non-ASCII advertisement would decode
to mojibake and re-encode to bytes the seller never signed.
