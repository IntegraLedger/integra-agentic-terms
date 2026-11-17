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

The gate calls `sign` only after the comparison matched and every check on the request passed, and, in `transact`, only
after your approver answered `true` for it; at most twice for one payment (a funding and then a voucher), and never for
the payment of a pairing whose build gives the buyer nothing to sign (it may sign that pairing's agreement payment).
Where the wallet builds the transaction and picks its expiry itself, the request carries the latest deadline it may
sign (`maxExpirationTimestampSecs`, `maxTtl`, `maxEpoch` or `maxEraPeriod`); a payment signed past it is discarded and
declined `past-ceiling`.

## Requests and answers

Each request has a `kind`. The kind says what is signed and what the answer is. The TypeScript type `SigningRequest` is
the union of every kind.

**Byte strings.** In TypeScript, the request is exactly as the binding built it: byte strings are `Uint8Array`, and a
few integers are `bigint`. In Python, every byte string in the request is `0x` and lower-case hex. In both languages,
an answer's byte strings are `0x` hex, except where the row names another form: base58, base64, or hex digits without
`0x`.

### EVM and Tempo

| Kind | What the signer signs | Answer |
| --- | --- | --- |
| `eip712` | EIP-712 typed data (`request.typedData`): an EIP-3009 transfer authorization, a Permit2 transfer, a channel voucher. An EVM session's funding by transfer authorization also carries `opening`, `{ payee, salt, authorizedSigner }`, which its nonce commits to with the payer and the token. | The 65-byte signature, `0x` hex. |
| `erc7710` | An ERC-7710 delegation request for the option. | `{ delegationManager, permissionContext, delegator }`, each `0x` hex. |
| `evm-call` | One contract call on the chain. With `broadcast: true` the signer sends it itself (a Spend Permission's `approve`, on its route `"transaction"`). | Without `broadcast`: the signed EIP-1559 transaction, `0x` hex, for the request's `chainId`; another chain is declined `signed-not-bound` (`evm/chain-mismatch`), as are bytes that are not an EIP-1559 transaction (`mpp/credential-malformed`). With `broadcast`: the transaction hash, `0x` hex. |
| `gateway-burn-intent` | A Circle Gateway burn intent: the salt's preimage, the `maxBlockHeight` the build computed from your floor inputs, and `challengeRequest`, the challenge's `request` as issued, whose hash the preimage commits to and from which the gate shows the amount, the recipient, the destination network and the most fee. The client adds its own values, computes the salt from the preimage and signs. | `{ source, sourceNetwork, destinationNetwork, maxFee, burnIntent, signature }`. A burn intent whose `maxBlockHeight` is not the one built is refused (`mpp/max-block-height-changed`), as is another `sourceNetwork` (`mpp/input-malformed`). |
| `tempo-call` | A Tempo `0x76` transaction with one call (a session's open). | The signed transaction, `0x` hex. |
| `tempo-key-authorization` | The digest of a Tempo key authorization, signed by the root key (a subscription). | The root key's signature, `0x` hex. |

### Other chains

| Kind | What the signer signs | Answer |
| --- | --- | --- |
| `solana-message` | A Solana v0 transaction message (`request.message`). | The payer's 64-byte Ed25519 signature, `0x` hex (base58 for the batch-settlement opening and voucher). |
| `solana-session-open` | The message of an MPP session's payment-channel `open` (`request.message`), with one Memo instruction carrying H's LCP string, its fee payer the challenge's `operator`, who co-signs and submits it. | The payer's 64-byte Ed25519 signature over the message, `0x` hex. |
| `ed25519-raw` | Raw Ed25519 over the bytes given (`request.message`), by the key `request.signer` names. | The 64-byte signature, base58. |
| `stellar-precondition` | A Soroban authorization's `preimage`, and the 40-byte `payload` of its signed-payload precondition: H, then the entry's nonce. | `{ entry, payload }`: the 64-byte Ed25519 signature over the preimage's SHA-256, and the one over the payload, raw, each `0x` hex. |
| `xrpl-tx` | An XRPL transaction as `txJson`. | The signed blob, hex digits without `0x`, as the XRP Ledger writes it, signed with a single key: a blob that carries `Signers` is declined `signed-not-bound`. The blob carries `NetworkID` as rippled requires of the network, none where its id is at most 1024 and that id above 1024; any other is declined `signed-not-bound` (`xrpl/network-mismatch`). |
| `xrpl-session-open` | A `PaymentChannelCreate` and the first claim. | `{ signedBlob, claimSignature }`, each hex digits without `0x`, as the XRP Ledger writes them, the blob signed with a single key and carrying no `NetworkID`, which rippled refuses on each network the challenge can name: one that carries it is declined `signed-not-bound` (`xrpl/network-mismatch`). |
| `xrpl-claim` | One claim on the session's payment channel, or a close's final claim, inside a `batch`: `{ channelId, drops, bytes }`, where `bytes` is `CLM\0`, the channel id and `drops` as a big-endian u64. | The signature over `bytes` by the channel's key, hex digits without `0x`. |
| `hedera-body` | A Hedera transaction body (`request.bodyBytes`), which the signer signs and never sends. | `{ publicKey, signature, type }`, with `type` `ed25519` or `ecdsa-secp256k1`, the key and signature `0x` hex. |
| `hedera-executor` | The executors, asset, payee, amount and `validBefore` for the buyer's transfer-executor tooling. | `{ payer, executor, authorization }`. |
| `algorand-txn` | An Algorand asset transfer whose note carries H. | The 64-byte Ed25519 signature, `0x` hex. |
| `aptos-transaction` | The option to pay, and `maxExpirationTimestampSecs`. The wallet builds and signs the scheme's own payment, expiring no later. | `{ transaction }`, base64: the transaction's BCS bytes, or x402's reference form. |
| `sui-transaction` | The option, a `pureInput` and `maxEpoch`. The wallet builds the payment, expiring no later than that epoch, adds the input, and signs. | `{ signature, transaction }`, each base64, as Sui serializes them. |
| `cardano-transaction` | The option, the auxiliary data and `maxTtl`. The wallet builds the payment, or the lock, with a TTL no later, attaches exactly those auxiliary data, and signs without broadcasting. | `{ transaction, nonce }`, the transaction as base64. Metadata that holds label 674 again, or a label-674 map that repeats a key, is declined `signed-not-bound`. |
| `near-delegate` | The NEP-461 hash of a delegate action whose `ft_transfer` memo carries H. | `{ keyType, bytes }`, the signature as `0x` hex. |
| `starknet-snip12` | SNIP-12 typed data for a SNIP-9 outside execution. | The account's signature, a list of felts. |
| `substrate-call` | The profile's call and `maxEraPeriod`, which the wallet signs as a v4 extrinsic with its own extensions and a mortal era no longer. | The extrinsic's bytes, `0x` hex. |
| `tron-txid` | The id of a TRC-20 transfer whose memo carries H. | The 65-byte secp256k1 signature `r ‖ s ‖ v`, `0x` hex. |
| `ton-w5` | The representation hash of a W5 wallet request. | The 64-byte Ed25519 signature, `0x` hex. |
| `casper-eip712` | CEP-3009 typed data whose nonce is H. | `{ publicKey, signature }`, each hex digits without `0x`, led by its one-byte algorithm tag (`01` or `02`). |
| `ccd-transfer` | A Concordium transfer whose memo carries H, which the wallet assembles. | The sender-signed V1 sponsored transaction in x402's wire form: with `@concordium/web-sdk`, `JSON.parse(Transaction.toJSONString(tx))`. |
| `stacks-contract-call` | A SIP-010 `transfer` whose memo is H, on the chain the request's `chainId` names. | The signed transaction's bytes, `0x` hex: 1 to 16,384 bytes, signed for `chainId` at that network's version, `0x00` on chain 1 (mainnet) and `0x80` on any other, as a Stacks node requires. Chain 1 is read as mainnet by the CAIP-2 convention, under which `stacks:1` is Stacks mainnet. Another chain id or version is declined `signed-not-bound` (`stacks/chain-mismatch`). |
| `bolt11-pay` | A BOLT11 invoice. Your Lightning node pays exactly this invoice. | The payment preimage: 64 lower-case hex digits, no `0x`. |

### Protocols without a chain signature

| Kind | What the signer signs | Answer |
| --- | --- | --- |
| `tap-field` | The nonce for the agent's RFC 9421 message signatures, under Visa's Trusted Agent Protocol or Mastercard Agent Pay: H followed by 32 random bytes. | `{ signatureInput, signature }`: the `Signature-Input` and `Signature` fields of the agent's checkout request, from whose nonce the pairing reads H. |
| `vic-reference` | The transaction reference `transactionReferenceId` the agent writes into its Visa Intelligent Commerce credential request. | `{ transactionReferenceId }`, as the credential payload Visa signs returns it. |
| `vi-checkout` | The agent's checkout payload, with the seller's `legalContext` written into it, for the agent to sign as its `checkout_jwt` (Mastercard Verifiable Intent, immediate, where the seller serves no `checkout_jwt`). | `{ checkout_jwt }`, whose payload segment is the base64url of the payload as `viJson` writes it. |
| `vi-checkout-mandate` | A Mastercard Verifiable Intent checkout mandate over the `checkout_jwt`. | `{ l2 }` from the user's wallet (immediate), or `{ l1, l2, l3b }` from the agent (autonomous). |
| `ap2-checkout-mandate` | The claims of a closed AP2 checkout mandate. | The mandate as issued, an SD-JWT string, or AP2's chained presentation: the open mandate's SD-JWT and the closed mandate's, joined by `~~`. The closed mandate is the one read. On `ap2/checkout-mandate/x402`, `{ checkout_mandate, payment }`: that mandate, and AP2's x402 bundle as your credential provider wrote it. |
| `ucp-checkout` | A UCP checkout for the buyer's AP2 mandate issuer. | The checkout mandate as issued, an SD-JWT string, or AP2's chained presentation: the open mandate's SD-JWT and the closed mandate's, joined by `~~`. The closed mandate is the one read. |
| `ucp-legal-context` | The `legal_context` member, `{ type: "sha256", value: H }`, that the platform writes into the request completing the checkout, beside that checkout (`ucp/checkout/agent-signed`). | `{ body, contentDigest }`: the completing request's JSON body as sent, with the member at its top level, and its `Content-Digest` field, which the agent's RFC 9421 signature covers. |
| `acp-allowance` | An ACP `delegate_payment` allowance. | The `delegate_payment` request the agent signed, as an object. |
| `batch` | Several requests, signed in order (a channel's opening and first voucher, an in-channel voucher). | A list of answers, in the same order. |

## Signers that move the payment

For some requests your signer's action moves the payment itself: a Lightning node paying an invoice, a signer that
broadcasts an `evm-call` marked `broadcast: true`. If
the gate declines after that (for example because the pairing does not read H from what came back), the decline carries
`moved`: the payment as signed, the ATR's bytes and their hash. Keep it, and present it again rather than signing a new
payment.

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
