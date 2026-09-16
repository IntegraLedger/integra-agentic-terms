# @integraledger/connector-conformance

**The conformance vectors for the Integra connector wire, and the digest that pins them.**

A platform that writes a connector against the Integra contract has to sign every request it sends and
refuse every request it receives that is not signed correctly. This package publishes the 22 vectors that
say what "correctly" means, so that the platform can establish its implementation is right **by running
them itself, on its own clock**, rather than by asking anyone.

⛔ **This package contains no connector.** It is the document, a digest, and a loader. A conformance
artifact that shipped a reference implementation beside the vectors would tempt a port to agree with the
implementation rather than with the contract — the same defect as a test asserting a constant against
itself. Your connector is the implementation under test; these are the inputs and the required answers.

**Version 0.1.0** · Apache-2.0 · Node ≥ 24

---

## What is in the document

`connector-conformance-v1.json` states the contract and then exercises it:

| field | what it is |
|---|---|
| `contractVersion` | the wire contract these vectors are drawn from |
| `signingStringShape` | `<t>.<label>.<rawBody>` — what the HMAC is computed over |
| `labels` | the label each operation binds inside the signature: `mint` → `connector/mint`, `observe` → `connector/observe` |
| `derivedFrom` | the request groups, operations and seams the 22 cases were drawn from, so you can see what is **not** covered |
| `count` | 22, and it is held equal to the length of `vectors` |
| `vectors` | one object per case — see below |

Each vector is a complete, self-contained request:

| field | what your connector does with it |
|---|---|
| `secret` | the signing key. ⚠️ A **published** conformance secret, fixed so the signature is reproducible; never a credential |
| `endpointOperation` | the operation of the endpoint the request arrived on |
| `rawBody` | ⛔ the exact bytes that were signed — do not parse and re-serialise them |
| `signatureHeader` | the `t=…,v1=…` header as sent, including the shapes that do not parse |
| `nowSeconds` | the instant your connector is to believe it is |
| `toleranceSeconds` | the skew it is to allow, in both directions |
| `expect` | `accept` or `reject` |
| `rejection` | the reason a refusal must give, or `null` |

## The four checks, in this order

The **order is part of the contract**, because it decides which reason a request is refused for — and the
reason is what somebody debugging a clock skew at two in the morning reads.

1. the header parses into `t` and `v1`, and `t` is a number → `malformed-header`
2. `|now − t| ≤ tolerance`, in **both** directions → `stale-timestamp`
3. the HMAC-SHA256 of `<t>.<label>.<rawBody>` under `secret` equals `v1` → `bad-signature`
4. the body's `operation` equals the endpoint's → `operation-mismatch`

⛔ **Step 3 hashes the raw body.** It does not parse it and it does not re-serialise it. The vector named
`raw-bytes-signed-not-reserialised` fails for any implementation that does: its body is pretty-printed and
carries a `/` and a non-ASCII character, which some languages' default JSON encoders escape.

⛔ **Step 4 is why the body is parsed at all**, and it happens only *after* the signature has verified — so
nothing touches attacker-shaped JSON before the HMAC has said the bytes are yours.

⭐ **Compare the parsed `t`, not the characters.** A connector that reproduced the raw characters instead
disagrees on `t=0300`, which is the sort of difference that shows up in production and never in a demo.

## Running them against your connector

The shape every port uses is **stdin in, stdout out, and nothing else** — no harness to install, no
framework to adopt, and nothing that has to know how your connector is wired:

```bash
# your connector's conformance entry point, in whatever language it is written in
your-conformance < node_modules/@integraledger/connector-conformance/src/connector-conformance-v1.json
{"conformanceVersion":1,"results":[{"id":"group-A-mint-accepts","outcome":"accept","rejection":null}, …]}
```

Your program reads the document, judges each vector with the code your connector really runs, and emits one
result per vector. You pass when every `outcome` and every `rejection` equals the vector's `expect` and
`rejection` — **both**. An implementation that refuses everything matches every `outcome` on the sixteen
refusals and is still wrong, which is why the reason is compared too.

The document is plain JSON and needs nothing from this package. If you are on Node, the loader here saves
you resolving the path and checks the digest on the way:

```ts
import {
  CONNECTOR_CONFORMANCE_V1_SHA256,
  loadVectors,
  vectorsPath,
} from "@integraledger/connector-conformance";

const doc = loadVectors(); // throws if the bytes are not the ones this version publishes
console.log(doc.count, doc.vectors.length, CONNECTOR_CONFORMANCE_V1_SHA256, vectorsPath());

for (const vector of doc.vectors) {
  const outcome: "accept" | "reject" = vector.expect;
  console.log(vector.id, outcome, vector.rejection);
}
```

## Verifying what you fetched

The digest ships three ways, and they are held equal to each other by this package's own suite:

- beside the document, as `connector-conformance-v1.json.sha256`, in `shasum -a 256 -c` format;
- as `CONNECTOR_CONFORMANCE_V1_SHA256`, a literal in the code;
- in this file:

```
feebda1eac16b5f25ce1150612b5c099a62706077b5b13d6332635dcef46e521  connector-conformance-v1.json
```

```bash
cd node_modules/@integraledger/connector-conformance/src
shasum -a 256 -c connector-conformance-v1.json.sha256
```

⛔ **A digest recomputed from the file it describes agrees with it by construction.** The value above is a
literal that was written down once; if the document ever moves without it moving, this package's own tests
go red before anything reaches a registry.

## What this is not

- **Not a certification.** Passing says your connector agrees with the contract on these 22 cases. It is
  not a statement that any record is enforceable, binding or lawful, and nothing here is one.
- **Not exhaustive.** `derivedFrom` says what the cases were drawn from. Read it before concluding that a
  behaviour is unconstrained because no vector names it.
- **Not versioned in place.** A changed contract gets a `v2` document. `connector-conformance-v1.json` is
  the bytes this digest names, permanently.

---

Apache-2.0. The Legal Context Protocol is co-stewarded by Integra Ledger and AAA-ICDR; the specification is
published at <https://legalcontextprotocol.org/standard> and is not part of this distribution.
