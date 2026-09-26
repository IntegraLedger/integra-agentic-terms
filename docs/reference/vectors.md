---
title: Vectors
description: The shared test cases that fix the gate's rules byte for byte, and how both gates run them.
---

Two implementations of one rule can compute two hashes. The vectors prevent that. They are JSON files of inputs and
expected outputs, shipped by `@integraledger/lcp` in its `vectors/` directory, and every expected value in them comes from
outside the code: a published specification's example, a standard's test value (the SHA-256 of `abc` from FIPS 180-2),
or a value computed with independent tools such as GNU coreutils `sha256sum`, `openssl dgst`, `eth-account` and `viem`,
each named in the file's `about`.

The TypeScript gate and the Python gate both run them. Where a vector names an expected hash, request, payment or decline,
both gates must produce exactly that.

## What they fix

| File | What it fixes |
| --- | --- |
| `core-vectors.json` | The ATR's bytes and their hash: assembly, SHA-256 and hash comparison, including a record changed by one byte. |
| `buyer.json` | The gate's own rows, below: the comparison, the fetch bounds, the build, the finish and the agreement exchange. |
| One file per pairing (`x402-exact-eip155-eip3009.json`, `mpp-charge-solana.json`, …) | The request the pairing builds with H, the payment the signer's answer completes, and where H sits in it. Each file's `buyer` section holds that pairing's changed-record row (B2) and build-and-sign row (B6). |
| `mpp-challenge.json` | The MPP challenge pieces every MPP pairing shares. |
| `decoder-caps.json` | The depth and size bounds of the rail decoders. |

## The buyer rows

`buyer.json` fixes an ATR `A` of 138 bytes, `C` (the same with byte 124 changed from `0x30` to `0x31`), a seller
document `D` advertising `hash(A)`, the published Anvil development key as the payer, and a fixed clock.

| Row | What it fixes |
| --- | --- |
| B1 | `hash(A)` is `0x8b1e1225…10072938`. |
| B2, B2b | A link that serves `C` while `D` advertises `hash(A)`: `hash-mismatch`, and the signer is never called. |
| B3, B4 | A body that is `A` parsed and re-serialised, by Python's `json.dumps` and by JavaScript's `JSON.stringify`: `hash-mismatch`. The gate hashes the bytes it received. |
| B5 | An advertised H in upper-case hex matches; the build receives the hash the gate computed, in lower case. |
| B6 | The request built from `D` (an EIP-3009 authorization whose nonce is `hash(A)`), its EIP-712 digest, the Anvil key's signature, and the payment `finish` returns. |
| B7 | `check` over B6's payment gives `hash(A)` with `A`, and `signed-not-bound` with `C`. |
| B8 | Where the seller advertises x402's `payment-identifier`, the payment carries a fresh 32-character identifier each time. |
| B9 | A payment whose signed contents carry another hash: `signed-not-bound`, and no payment is returned. |
| B10 | An `http://` link: declined before any fetch. |
| B11 | A redirect, a `404` or a failed fetch: `atr-unfetchable`, and no signer call. |
| B12, B13 | A body of exactly 1 MiB is read and compared; one byte more, declared or streamed, is `atr-too-large` and the stream is cancelled. |
| B14 | A link that never answers: `atr-unfetchable` after 10 seconds. |
| B15 | A signer that throws: `signer-failed`. |
| B16 | An account on another network or chain: `no-payable-option`, with no fetch. |
| B17 | A binding the gate does not serve: `pairing-not-supported`. |
| B18 | A `payment-identifier` that already holds an id, or is not an object: the identifier cannot be written, and no payment is returned. |
| BA1 | A pairing whose payment is not a public proof: the agreement is paid first (one signature), then the payment (one signature). |
| BA2 | An agreement URL that advertises another hash: `hash-mismatch`, nothing signed. |
| BA3 | An agreement that stays `202`: the same payment is re-sent every 2 seconds until `maxTimeoutSeconds` plus 180 seconds, then `agreement-pending`; the main payment is never signed. |
| BA4 | A receipt for another hash: `agreement-failed`; the main payment is never signed. |
| BA5 | An `http://` agreement URL: `link-not-https`, with no fetch. |
| BA6 | A pairing whose payment is itself a public proof ignores an agreement URL in the offer. |
| BA7 | `transact` returns the agreement's receipt beside the payment. |

## Running them

From a checkout, after `pnpm install`:

```sh
pnpm --filter @integraledger/terms test
pnpm --filter @integraledger/terms-mcp test

cd agentic-terms-py
uv run --locked --python 3.11 pytest -q
uv run --locked --python 3.14 pytest -q
```

The TypeScript tests read the vectors from the installed `@integraledger/lcp`. The Python tests read the same files from
`agentic-terms/node_modules/@integraledger/lcp/vectors`, so both gates always run one copy.
