---
"@integraledger/agentic-terms": minor
"@integraledger/lcp-mcp-server": minor
---

The peer floor moves to 0.19.0 — the line, the pins and the pages in one change

The published protocol line moved and this repository's ranges did not, so the scheduled
`protocol-currency` job went red on `main` and will stay red on every six-hour sample until the line moves.
Under the floor rule the peer must EQUAL the exercised dev pin, so neither side can drift alone.

    protocol devDependencies   0.18.3  -> 0.19.0   (11 pins, the exercised line)
    protocol peers + shipped   ^0.18.3 -> ^0.19.0  (18 ranges)
    the three published pages that state the range

⛔ **WHY A CARET IS NOT A FLOOR HERE.** On a `0.x` version a caret pins the MINOR, so `^0.18.3` excludes
`0.19.0` outright. A consumer holding this package alongside the newer protocol gets **no error**: the
package manager resolves a SECOND protocol line beside the first, and two copies of `lcp-binding-core`
break `instanceof` across the boundary — the failure this floor rule exists to prevent, and one that
surfaces only downstream, after the version is published.

`M` Planted: one peer left at `^0.18.3` against a line pinned at `0.19.0`, and `check:wire` exits **1** on
three counts at once — the dev pin outside its own peer range, the peer not equal to the exercised line,
and two distinct peer ranges in one manifest, *"and with several there is no single answer to state"*.

## ⭐ What did NOT move, each measured rather than assumed

**The catalog does not follow this time.** `check:shared-pins` is green unchanged: the published `0.19.0`
line declares the same shared dependency this workspace already pins, so the sentence that required a
`zod` move at `0.18.3` requires nothing here. The rule did not change; the published line did not either.

**The wire seal is untouched.** `check:wire` reports the identities still match, so nothing a counterparty
must write changed with this bump — which is what the seal exists to tell you, and it is only worth
anything because it is read from the INSTALLED packages rather than from the manifests.

**Nothing here consumed what the authority package replaced.** `0.19.0` carries that package's move from
projecting an authority form to recording an attestation: `readAttestationProfile` is **gone** from its
exports, and seven names arrive alongside a new optional member on `ResolutionStep`. Measured over this
repository's shipped sources (`git grep -o` over `packages/*/src/**`):

    readAttestationProfile, AttestationProfile, ProfiledAttestation,
    ResolutionStep, IdentityResolution, terminatesInAccountableParty,
    isConsequentialConformant, walkChain                              0 each
    CONTROL — Assurance, the one symbol this repository does use     26

Three source files name `lcp-authority` at all, all in `agentic-terms`, and every one of them imports the
`Assurance` type and nothing else. That type's declaration is **byte-identical** across the two versions,
compared from the two published tarballs. ⇒ The bump is type-compatible here, and `typecheck` says so over
the installed line rather than over a fixture.
