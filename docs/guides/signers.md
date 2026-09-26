---
title: Signers
description: The signer contract, every kind of signing request the gate hands out, and the answer each one takes.
---

The gate never holds a key. It hands your signer one request at a time, each built with the hash the gate computed,
and it reads the answer back to complete the payment. This page is the contract between the two.

## The contract

```ts no-run
import type { Signature, SigningRequest } from "@integraledger/terms";

interface Signer {
  /** The payer, CAIP-10: `eip155:84532:0xf39F…2266`. */
  readonly account: string;
  /** Signs exactly `request`. */
  sign(request: SigningRequest): Promise<Signature>;
}
```

In Python, any object with an `account` string and an `async def sign(self, request)` method is a signer.

- **`account`** is [CAIP-10](https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-10.md): the chain namespace,
  the network reference and the address. It chooses the option the gate pays, and for most pairings it is the payer.
- **`sign(request)`** signs exactly what it is handed. It changes nothing: not a field, not an amount, not a deadline.
  If it cannot sign a request, it throws (TypeScript) or raises (Python), and the gate declines with `signer-failed`.

The gate calls `sign` only after the comparison matched, at most twice for one payment (a funding and then a voucher),
and never for a pairing whose build gives the buyer nothing to sign.

## Requests and answers

Each request has a `kind`. The kind says what is signed and what the answer is. The TypeScript type `SigningRequest` is
the union of every kind.

**Byte strings.** In TypeScript, the request is exactly as the binding built it: byte strings are `Uint8Array`, and a
few integers are `bigint`. In Python, every byte string in the request is `0x` and lower-case hex. In both languages,
every byte string in an answer is `0x` hex.

### EVM and Tempo

| Kind | What the signer signs | Answer |
| --- | --- | --- |
| `eip712` | EIP-712 typed data (`request.typedData`): an EIP-3009 transfer authorization, a Permit2 transfer, a channel voucher. | The 65-byte signature, `0x` hex. |
| `erc7710` | An ERC-7710 delegation request for the option. | `{ delegationManager, permissionContext, delegator }`, each `0x` hex. |
| `evm-call` | One contract call on the chain. With `broadcast: true` the signer sends it itself. | Without `broadcast`: the signed EIP-1559 transaction, `0x` hex. With `broadcast`: the transaction hash, `0x` hex. |
| `evm-calls` | Several calls, in order, which the signer broadcasts (a session's opening). | The opening's transaction hash, `0x` hex. |
| `gateway-burn-intent` | A Circle Gateway burn intent. The client computes the salt from the preimage the request gives and signs. | `{ source, sourceNetwork, destinationNetwork, maxFee, burnIntent, signature }`. |
| `tempo-call`, `tempo-calls` | A Tempo `0x76` transaction with one call, or several in order (a charge with splits). With `broadcast: true` the signer sends it. | Without `broadcast`: the signed transaction, `0x` hex. With `broadcast`: `{ hash, landed }`, the hash it sent and, where it has it, the landed receipt `{ transaction, blockNumber, logs }`. |
| `tempo-key-authorization` | The digest of a Tempo key authorization, signed by the root key (a subscription). | The root key's signature, `0x` hex. |

### Other chains

| Kind | What the signer signs | Answer |
| --- | --- | --- |
| `solana-message` | A Solana v0 transaction message (`request.message`). | The payer's 64-byte Ed25519 signature, `0x` hex (base58 for the batch-settlement opening and voucher). |
| `solana-session-open` | The values of an MPP session opening, which the buyer's channel client composes into an `open`. | The open payload. |
| `ed25519-raw` | Raw Ed25519 over the bytes given (`request.message`), by the key `request.signer` names. | The 64-byte signature, base58. |
| `stellar-auth` | A Soroban authorization preimage (`request.preimage`). | The 64-byte Ed25519 signature over its SHA-256, `0x` hex. |
| `xrpl-tx` | An XRPL transaction as `txJson`. | The signed blob, `0x` hex. |
| `xrpl-session-open` | A `PaymentChannelCreate` and the first claim. | `{ signedBlob, claimSignature }`, `0x` hex. |
| `hedera-body` | A Hedera transaction body (`request.bodyBytes`). With `broadcast: true` the signer signs and sends it. | `{ publicKey, signature, type }`, with `type` `ed25519` or `ecdsa-secp256k1`. With `broadcast`: `{ transactionId }`. |
| `hedera-executor` | The executors, asset, payee, amount and `validBefore` for the buyer's transfer-executor tooling. | `{ payer, executor, authorization }`. |
| `hedera-session-open` | An MPP session opening on Hedera, which the signer broadcasts, and its zero voucher. | `{ openTx, signature }`, with `landed` where the signer has the opening's receipt. |
| `algorand-txn` | An Algorand asset transfer whose note carries H. | The 64-byte Ed25519 signature, `0x` hex. |
| `aptos-transaction` | The option to pay. The wallet builds and signs the scheme's own payment. | `{ transaction }`. |
| `sui-transaction` | The option and a `pureInput`. The wallet builds the payment, adds the input, and signs. | `{ signature, transaction }`. |
| `cardano-transaction` | The option and the auxiliary data. The wallet builds the payment with a TTL and signs without broadcasting. | `{ transaction, nonce }`. |
| `near-delegate` | The NEP-461 hash of a delegate action whose `ft_transfer` memo carries H. | `{ keyType, bytes }`, the signature as `0x` hex. |
| `starknet-snip12` | SNIP-12 typed data for a SNIP-9 outside execution. | The account's signature, a list of felts. |
| `substrate-call` | The profile's call, which the wallet signs as a v4 extrinsic with its own extensions. | The extrinsic's bytes, `0x` hex. |
| `tron-txid` | The id of a TRC-20 transfer whose memo carries H. | The 65-byte secp256k1 signature `r ‖ s ‖ v`, `0x` hex. |
| `ton-w5` | The representation hash of a W5 wallet request. | The 64-byte Ed25519 signature, `0x` hex. |
| `casper-eip712` | CEP-3009 typed data whose nonce is H. | `{ publicKey, signature }`, each hex with its one-byte algorithm tag. |
| `ccd-transfer` | A Concordium transfer whose memo carries H, which the wallet assembles. | The sender-signed sponsored transaction, in the Concordium SDK's `signableToJSON` form. |
| `stacks-contract-call` | A SIP-010 `transfer` whose memo is H. | The signed transaction's bytes, `0x` hex. |
| `bolt11-pay` | A BOLT11 invoice. Your Lightning node pays exactly this invoice. | The payment preimage: 64 lower-case hex digits, no `0x`. |

### Protocols without a chain signature

| Kind | What the signer signs | Answer |
| --- | --- | --- |
| `tap-field` | The `lcp-hash` field for a Visa Trusted Agent Protocol `agent-payer-auth` message signature. | `{ signatureInput, signature, lcpHash }`, `lcpHash` being every `lcp-hash` field line sent, in order. |
| `vi-checkout-mandate` | A Mastercard Verifiable Intent checkout mandate. | `{ l2 }` from the user's wallet (immediate), or `{ l1, l2, l3b }` from the agent (autonomous). |
| `ap2-checkout-mandate` | The claims of a closed AP2 checkout mandate. | The mandate as issued, an SD-JWT string. |
| `ucp-checkout` | A UCP checkout for the buyer's AP2 mandate issuer. | The checkout mandate as issued, an SD-JWT string. |
| `acp-allowance` | An ACP `delegate_payment` allowance. | The `delegate_payment` request the agent signed, as an object. |
| `batch` | Several requests, signed in order (a channel's opening and first voucher, an in-channel voucher). | A list of answers, in the same order. |

## Signers that move the payment

For some requests your signer's action moves the payment itself: a Lightning node paying an invoice, a signer that
broadcasts an `evm-call`, `tempo-call` or `hedera-body` marked `broadcast: true`, a session opening the signer sends. If
the gate declines after that (for example because what came back does not carry H), the decline carries `moved`: the
payment as signed, the ATR's bytes and their hash. Keep it, and present it again rather than signing a new payment.

## A signer for several kinds

A real signer dispatches on `kind` and refuses what it does not handle:

```ts
import type { Signature, Signer, SigningRequest } from "@integraledger/terms";
import { privateKeyToAccount } from "viem/accounts";

// The published Anvil development key. Never use it for real funds.
const wallet = privateKeyToAccount("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

const signer: Signer = {
  account: `eip155:84532:${wallet.address}`,
  async sign(request: SigningRequest): Promise<Signature> {
    switch (request.kind) {
      case "eip712":
        return wallet.signTypedData(request.typedData as Parameters<typeof wallet.signTypedData>[0]);
      case "batch": {
        const answers: Signature[] = [];
        for (const each of request.requests) answers.push(await this.sign(each as SigningRequest));
        return answers;
      }
      default:
        throw new Error(`this signer does not sign ${request.kind}`);
    }
  },
};

console.log(signer.account);
```

```text output
eip155:84532:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
```

The [rails guide](./rails.md) lists, for each pairing, the kind its request has and the inputs its build reads.
