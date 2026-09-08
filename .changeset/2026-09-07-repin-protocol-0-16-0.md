---
"@integraledger/agentic-terms": minor
"@integraledger/lcp-mcp-server": minor
---

Repin the protocol line to 0.16.0, and move the peer floor with it.

⛔ THE PEER RANGE IS THE POINT, NOT THE DEV PIN. These packages declared `^0.15.0` peers, and on a `0.x`
version a caret is MINOR-LOCKED — `^0.15.0` is `>=0.15.0 <0.16.0`. A consumer that repinned the protocol
to 0.16.0 could therefore not satisfy them, and the resolver's answer was not an error but a SECOND COPY
of the protocol line at 0.15.1 alongside the 0.16.0 one. Measured in a consuming workspace: 13
package/version pairs resolving to 0.15.1 under pins that every manifest wrote as 0.16.0. Two copies of
one protocol package in a single tree also break `instanceof` across the boundary between them, so the
resolver's quiet answer is worse than a refusal.

So this is a minor rather than a patch: it is a change to what a consumer's tree must contain.

The dev pins move to 0.16.0 in the same commit, because a peer range and the version the package is built
and tested against are one statement, not two.
