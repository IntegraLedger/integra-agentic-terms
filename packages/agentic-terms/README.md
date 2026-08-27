# @integraledger/agentic-terms

**Integra Agentic Terms** — verify before sign, as a type and as a runtime guarantee.

None of the agentic commerce protocols carries a fingerprint of the terms it is settling. LCP defines one:
the `atrHash`, a SHA-256 digest over the terms document, which a seller advertises alongside the terms.
This package is the buyer side of that check — it fetches the terms the seller advertised, recomputes the
digest over the bytes actually served, and halts before any signing key is invoked if the two disagree.

```bash
npm install @integraledger/agentic-terms
```

> **Free and open source (Apache-2.0). No account, no key, no token, nothing to sign up for.**
>
> **It works against any seller** — the check is over what a seller publicly advertises, so it is useful
> whether or not that seller has ever heard of Integra. Nothing here calls home: no telemetry, no callback,
> no network request other than fetching the terms the seller pointed you at.

```ts
import {
  type BuyerPolicy,
  type GatedSigner,
  makeCachingFetcher,
  nodeDnsLookup,
  parseProposalFromChallenge,
  transact,
} from "@integraledger/agentic-terms";

declare const challenge: unknown; // the 402 body the seller returned
declare const policy: BuyerPolicy; // your risk posture — caps, jurisdictions, forbidden clauses
declare const signer: GatedSigner; // your key. Reachable only on Proceed.

const now = () => new Date().toISOString();
const fetcher = makeCachingFetcher({ httpFetch: fetch, now, lookup: nodeDnsLookup });

const proposal = parseProposalFromChallenge(challenge, {
  level: 3,
  sellerAssurance: "domain-controlled",
});
const result = await transact(proposal, policy, { fetcher, now }, signer);
// result.kind === "signed" only on Proceed; on Decline or Escalate the signer is never called.
```

Two properties do the work. The typed proposal **cannot** carry natural-language prose, so the terms body
can never reach policy evaluation — the prompt-injection boundary is architectural rather than a matter of
discipline. And a step's four-valued status maps totally onto a disposition: a failure always declines, and
gaps are resolved by the buyer's stated policy, never by a silent default.

The terms fetcher is HTTPS-only, refuses redirects, checks every resolved address is public unicast on every
network fetch, and caps the body while streaming. Viem-free: the chain reader for post-settlement mechanical
verification is injected.

### Runs wherever your agent runs — with one dependency caveat

**This package's own source imports no Node built-in.** The one Node-specific helper, `nodeDnsLookup`, is
imported lazily and injected rather than sitting at the top of the graph, so a build that never calls it
never pulls `node:dns` in. Supply your own `HostLookup` and the public-unicast check works on a runtime with
no DNS module at all. That much is enforced by the code and is the part worth relying on.

**One Node built-in does arrive transitively**, and the honest statement is that it is a dependency's, not
ours: `@integraledger/lcp-evidence` re-exports its CAR support from its index, which pulls `multiformats`'
Node SHA-2 build, which statically imports `node:crypto`. So:

| Target | Works | How we know |
|---|---|---|
| Node | yes | **measured** — every release runs the gate's whole decision here |
| Bun | yes | **measured** — same run, same assertions |
| Deno | yes | **measured** — same run, same assertions |
| Workers with `nodejs_compat` | yes — `node:crypto` is polyfilled | reasoned from the import graph, not measured |
| A bundler honouring `multiformats`' `browser` export condition | yes — it maps to the browser SHA-2 build | reasoned from the export conditions, not measured |
| A plain unbundled ESM import in a browser or service worker | **no** | reasoned — `node:crypto` has nothing to resolve to |

The measured rows run against **the packed tarball**, installed the way you would install it, with the
protocol line resolved from npmjs — not against this repository's own tree. Both halves of the guarantee are
asserted on each runtime, because a runtime where the gate refused everything would pass a check that only
looked for the halt: tampered terms must halt with the signer never reached, and matching terms must sign
with the signer reached exactly once.

The gate needs `fetch` and Web Crypto and nothing else of its own. Removing the last hop is an upstream
change — a subpath export on `lcp-evidence` so importing one predicate does not drag CAR and `multiformats`
into every consumer's bundle — and until it lands, the table above is the claim.

### The gate is exactly as trustworthy as the ports you give it

`GatePorts` is a trust boundary, not just a seam for testing. `fetcher` decides which bytes the fingerprint
is recomputed over, so a fetcher that returns the wrong body defeats verification completely; `now` dates
every entry in the record. This is not a weakness to fix — injection is what keeps the gate viem-free and
runnable off Node — but it is a property worth stating rather than discovering. Use the `makeCachingFetcher`
shipped here unless you have a specific reason not to, and hold your ports to the standard you hold the key
they protect.

## Reading any protocol's document

A buyer that does not know which protocol it is on has two universal entry points, both dispatching through
`@integraledger/lcp-placements` so that a protocol this package supports is precisely one the build can also
place a reference into.

```ts
import {
  detectProtocol,
  parseProposalUniversal,
  readAdvertisedTerms,
} from "@integraledger/agentic-terms";

declare const wire: unknown; // whatever document the counterparty handed you

detectProtocol(wire); // "acp" | … | undefined — never a guess
readAdvertisedTerms("ucp", wire); // { protocol, advertisedAtrHash, legalContextUrl }
parseProposalUniversal(wire, { level: 3, sellerAssurance: "domain-controlled" }); // the full GateProposal
```

**`readAdvertisedTerms` is universal; `parseProposalUniversal` is not, and the difference is a fact about
the protocols.** The reference is read out of the protocol's own `PlacementManifest` — every carrier it
declares, not the first one that answers — so all nine registered protocols work and nothing is listed here.
A `GateProposal` additionally carries an OFFER, and an amount with its unit is protocol-native economics no
manifest declares: x402 quotes it in `accepts[].amount`, ACP in the `totals` row typed `total`, and the
other seven each differently again.

Four protocols are parsed into a full `GateProposal` today — **x402, ACP, AP2 and MPP**. Two of the four
are reached through `parseProposalUniversal`; **AP2 and MPP are reached by name**, because naming is what
their documents require:

```ts
import { parseProposalFromChallenge, parseProposalFromAcpCheckout,
         parseProposalFromAp2Envelope, parseProposalFromMppRequest } from "@integraledger/agentic-terms";
```

`parseProposalFromMppRequest` reads the MPP `request` body — the payload a `WWW-Authenticate: Payment`
challenge carries in its `request` auth-param. It takes `methodDetails.atrHash` and
`methodDetails.legalContextUrl`, the fields `placement-mpp` declares, and the offer from `amount` and
`currency`, which the charge intent defines as base units of a currency-or-asset identifier. It is by-name
because MPP's own identity lives in the challenge rather than the body: an amount-and-currency pair is the
shape of nearly every payment document, so nothing in the body says "MPP". The remaining protocols refuse by
name and say why.

Four answers are worth stating plainly, because each is a place a friendlier library would guess:

- **Ambiguity refuses.** Detection collects every discriminant that fires, never the first. An AP2 envelope
  *is* an A2A message, and a UCP checkout response shares `id`, `status`, `currency`, `totals` and
  `line_items` with an ACP session — so those documents come back named twice, and the caller has to say
  which protocol it is on rather than being handed a coin flip. The two overlaps differ in strength: the
  ACP/UCP one is contingent on the document, while `ap2`'s rule is a strict subset of `a2a`'s, so **every**
  AP2 envelope matches both and none is reachable through `parseProposalUniversal`. AP2 is a detect-and-name
  protocol here; `parseProposalFromAp2Envelope` exists and is called by name.
- **An absent terms URL says WHICH absence it is.** `legalContextUrl` is a union — `read`,
  `no-field-declared`, or `declared-fields-empty` — because a bare `undefined` conflates two different
  facts. `no-field-declared` is a fact about the PROTOCOL: it has nowhere to put a locator, and no document
  of that protocol can be faulted for lacking one. `declared-fields-empty` is a fact about THIS DOCUMENT:
  the protocol has room and this seller left every declared slot empty. Reporting the second as the first
  would blame a protocol for a seller's silence.

  It used to carry a fourth state, `undeclared-at-answering-carrier`, and that state is gone because the
  defect requiring it is fixed. The manifest's terms-URL member was singular, so x402 could declare only one
  of its two slots: a §C.4-illustrated challenge advertising in `accepts[].extra` really does carry a terms
  URL, while the single declared path sat empty inside `extensions` — and calling that "no terms advertised"
  would have asserted a silence this reader could not see. The member is plural now, every declared slot is
  read and reconciled, and a slot riding a container the placement owns is declared on that container. There
  is no carrier a declaration fails to reach, so the state is unreachable rather than merely unused.
- **Carrier disagreement refuses.** Where a protocol declares more than one carrier, all of them are read
  and compared. Two different hashes on one document would let a seller advertise different terms to
  different readers of it, so this is deliberately stricter than the placement adapter's own `extract`,
  which answers with the canonical field and does not adjudicate the host's document.
- **A located-but-unattested carrier is not a reference.** UCP's `links[type=terms_of_service]` entry is a
  discovery carrier: it says where the terms are and attests nothing, and it is skipped rather than accepted
  as a weaker answer.

One protocol carries nothing that names it — MPP, whose document is the decoded `request` body of a charge
challenge, an amount and a currency with no protocol marker (its identity lives in the `WWW-Authenticate`
challenge one layer out). `detectProtocol` returns `undefined` for it and `PROTOCOL_DISCRIMINANTS` records
why, with the citation. Naming it yourself reads it fine.

Part of [Integra Agentic Terms](https://github.com/IntegraLedger/integra-agentic-terms).
