---
title: Rails
description: What each rail needs from the buyer — the account form, the signing request, and the inputs the build reads.
---

Most pairings need nothing from you beyond the seller's document and your signer. Where a build needs a value only the
buyer can supply (a recent blockhash, an account sequence, a deposit), you pass it in `inputs`. This page lists, rail by
rail, the account form each pairing accepts, the kind of request your signer receives, and every input the build reads.

A missing or malformed input declines with `no-payable-option` and a detail ending in `/input-missing`, before any
fetch of the ATR. Input values are JSON: a **decimal** is a string of digits (`"1000000"`), an **integer** is a JSON
number, **hex** is `0x` followed by hex digits.

The [pairings reference](../reference/pairings.md) gives each pairing's binding export, its Python constant, and what
its payment proves. The [signers guide](./signers.md) gives the answer each request kind takes.

## Accounts

The signer's `account` is CAIP-10. Its namespace selects the pairings it can pay:

| Namespace | Rails | Example |
| --- | --- | --- |
| `eip155` | EVM chains, Tempo, and MPP's EVM, Tempo and USDC pairings | `eip155:84532:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266` |
| `solana` | Solana | `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:<base58 address>` |
| `stellar`, `xrpl`, `hedera`, `algorand`, `aptos`, `sui`, `near`, `starknet`, `polkadot`, `tron`, `tvm`, `cardano`, `casper`, `ccd`, `stacks` | The chain of that name (`tvm` is TON, `ccd` is Concordium) | `<namespace>:<network>:<address>` |
| `lnbtc` | Lightning | `lnbtc:000000000019d6689c085ae165831e93:<node id>` |
| any | Card, AP2, UCP, ACP and ACK pairings, where the account names the buyer | |

## EVM

| Pairing | Request | Inputs |
| --- | --- | --- |
| `x402/exact/eip155/eip3009` | `eip712` | none |
| `x402/exact/eip155/permit2` | `eip712` | none |
| `x402/exact/eip155/erc7710` | `erc7710` | none |
| `x402/exact/eip155/erc7710-salt` | `erc7710` | none |
| `x402/upto/eip155/permit2` | `eip712` | none |
| `x402/auth-capture/eip155/eip3009` | `eip712` | none |
| `x402/auth-capture/eip155/permit2` | `eip712` | none |
| `x402/batch-settlement/eip155` | `batch` of two `eip712`: the opening's token authorization, then the first voucher | `payerAuthorizer` (address, required); `deposit` (decimal, required unless the option's `extra.minDeposit` sets it); `maxDeposit` (decimal, optional: a larger deposit is refused); `authSalt` (32-byte hex, optional: drawn at random otherwise) |
| `mpp/charge/evm/authorization` | `eip712` | `tokenDomain` (object, required: the token's EIP-712 `name` and `version`) |
| `mpp/charge/evm/permit2` | `eip712` | `spender` (string, required: the seller server's submitting address) |
| `mpp/charge/evm/transaction` | `evm-call` | none |
| `mpp/charge/evm/hash` | `evm-call`, broadcast by the signer | none |
| `mpp/charge/usdc/evm` | `eip712` | `tokenDomain` (object, required) |
| `mpp/charge/usdc/gateway` | `gateway-burn-intent` | none |
| `mpp/session/evm` | two steps: the funding (`eip712`, or `evm-calls` broadcast by the signer), then the first voucher (`eip712`) | `deposit` (decimal, required); `authorizedSigner` (address, optional); `credentialType` (`authorization`, `permit2` or `hash`, optional); `tokenDomain` (object, optional) |

## Tempo

| Pairing | Request | Inputs |
| --- | --- | --- |
| `mpp/charge/tempo/memo` | `tempo-call`, or `tempo-calls` for a charge with splits | `clientId` (string, optional) |
| `mpp/charge/tempo/push` | `tempo-call` or `tempo-calls`, broadcast by the signer | `clientId` (string, optional) |
| `mpp/session/tempo` | two steps: the signed open transaction (`tempo-call`), then the first voucher (`eip712`) | `deposit` (decimal, required); `authorizedSigner`, `credentialType`, `tokenDomain` (optional) |
| `mpp/subscription/tempo` | `tempo-key-authorization` | none |

## Solana

| Pairing | Request | Inputs |
| --- | --- | --- |
| `x402/exact/solana` | `solana-message` | `decimals` (integer) and `tokenProgram` (string): the mint's; `recentBlockhash` (string, required unless the option's `extra.recentBlockhash` names one); `computeUnitLimit` (integer, optional); `computeUnitPrice` (decimal, optional) |
| `x402/upto/solana` | `solana-message` | `openSlot` (decimal), `tokenProgram` (string), `recentBlockhash` (string); `nonce` (decimal, optional: a random u64 otherwise); `computeUnitLimit`, `computeUnitPrice` (optional) |
| `x402/batch-settlement/solana` | `batch`: the opening's `solana-message`, then the first voucher's `ed25519-raw` | `payerAuthorizer` (string), `openSlot` (decimal), `tokenProgram` (string); `recentBlockhash` (unless the option names one); `deposit` (unless `extra.minDeposit` sets it); `maxDeposit`, `salt`, `computeUnitLimit`, `computeUnitPrice` (optional) |
| `mpp/charge/solana` | `solana-message` | `decimals`, `tokenProgram`, `recentBlockhash`, each required only where the request's `methodDetails` leaves it out (none for native SOL besides the blockhash); `computeUnitLimit`, `computeUnitPrice` (optional) |
| `mpp/charge/usdc/solana` | `solana-message` | as `mpp/charge/solana`, read from `methodDetails.solana` |
| `mpp/session/solana` | `solana-session-open`; with an `operator` voucher signer, then `ed25519-raw` for the session proof | `deposit` (decimal, optional) |

## Stellar

| Pairing | Request | Inputs |
| --- | --- | --- |
| `x402/exact/stellar` | `stellar-auth` | `simulatedXdr` (string: your simulated `transfer` transaction), `currentLedger` (integer) |
| `mpp/charge/stellar` | `stellar-auth` | `simulatedXdr`, `currentLedger` |

## XRP Ledger

| Pairing | Request | Inputs |
| --- | --- | --- |
| `x402/exact/xrpl` | `xrpl-tx` | `fee` (decimal), `lastLedgerSequence` (integer), and `sequence` (integer) or, where the option's `extra.assetTransferMethod` is `ticketSequence`, `ticketSequence` (integer) |
| `mpp/charge/xrpl` | `xrpl-tx` | `fee` (decimal), `sequence` (integer), `lastLedgerSequence` (integer) |
| `mpp/session/xrpl` | `xrpl-session-open` | `deposit` (decimal) and `xrpl` (object): `publicKey` (hex), `settleDelay` (integer), `fee` (decimal), `sequence` (integer), `lastLedgerSequence` (integer), `cancelAfter` (integer, optional) |

## Hedera

| Pairing | Request | Inputs |
| --- | --- | --- |
| `x402/exact/hedera` | `hedera-body` | `node` (string), `validStart` (object: `seconds` decimal, `nanos` integer), `maxFee` (decimal); `decimals` (integer, optional) |
| `x402/exact/hedera/transfer-executor` | `hedera-executor` | none |
| `mpp/charge/hedera` | `hedera-body`; with `credentialType: "hash"`, broadcast by the signer | `node`, `validStart`, `maxFee`; `clientId` (string, optional); `credentialType` (`transaction` or `hash`, optional) |
| `mpp/session/hedera` | `hedera-session-open`, broadcast by the signer | `deposit` (decimal) |

## Other chains

| Pairing | Request | Inputs |
| --- | --- | --- |
| `x402/exact/algorand` | `algorand-txn` | `params` (object: algod's `firstValid` and `minFee` and `feePerByte` as decimals, `genesisHash`, `genesisId`) |
| `x402/exact/aptos` | `aptos-transaction`: the wallet builds and signs the scheme's payment | none |
| `x402/exact/sui` | `sui-transaction`: the wallet builds the payment and adds the request's `pureInput` | none |
| `x402/exact/near` | `near-delegate` | `publicKey` (string), `accessKeyNonce` (decimal), `finalHeight` (decimal): from your RPC |
| `mpp/charge/nearintents` | none: the comparison is the buyer's whole step | none |
| `x402/exact/starknet` | `starknet-snip12` | none |
| `x402/exact/polkadot/lcp-assets-remark` | `substrate-call` | none |
| `x402/exact/tron/lcp-trc20-memo` | `tron-txid` | `refBlock` (object: `{ number, id }` of a recent block), `feeLimit` (decimal) |
| `x402/exact/tvm` | `ton-w5` | `walletId` (integer), `seqno` (integer), `jettonWallet` (string), `attachNanotons` (decimal); `stateInit` (base64 BoC, for a wallet not yet deployed) |
| `x402/exact/cardano` | `cardano-transaction` | none |
| `x402/exact/casper` | `casper-eip712` | none |
| `x402/exact/ccd` | `ccd-transfer` | none |
| `mpp/charge/usdc/stacks` | `stacks-contract-call` | none |

## Lightning

| Pairing | Request | Inputs |
| --- | --- | --- |
| `x402/exact/lnbtc` | `bolt11-pay` | `request` (object, required): your own request, from which the gate recomputes x402's request hash. For HTTP, `{ method, url, body?, headers? }`; for MCP, `{ server, name, arguments?, meta? }`. |
| `x402/exact/lnbtc/invoice-named` | `bolt11-pay` | `request`, as above |
| `mpp/charge/lightning` | `bolt11-pay` | none |
| `mpp/session/lightning` | `bolt11-pay` for the deposit invoice | `returnInvoice` (string, required) |

Your node moves the payment when it pays the invoice. A decline after that carries `moved`.

On `x402/exact/lnbtc/invoice-named` the ATR itself names the invoice. The gate pays only when the ATR's bytes are one
JSON object whose first members are `atrVersion`, `id` and `x402`, in that order, with no member name repeated, and
whose `x402` slot holds the option's invoice; otherwise it declines `offer-unreadable` with `ln/invoice-not-named`
before your node is asked to pay. Every JSON reader then finds the same `x402` slot, since RFC 8259 leaves a repeated
name to each reader.

## Cloudflare

| Pairing | Request | Inputs |
| --- | --- | --- |
| `x402/batch-settlement/cloudflare` | none: the build is the payment, and your agent's HTTP message signature signs the request that carries it | none |

## Cards and Stripe

| Pairing | Request | Inputs |
| --- | --- | --- |
| `card/visa-tap` | `tap-field` | none |
| `card/mastercard-vi/immediate` | `vi-checkout-mandate` (the user's L2) | none |
| `card/mastercard-vi/autonomous` | `vi-checkout-mandate` (the agent's L3b) | none |
| `card/seller-reference` | none: the comparison is the buyer's whole step | none |
| `mpp/charge/card` | none | none |
| `mpp/charge/stripe` | none | none |
| `mpp/subscription/stripe` | none | none |

## Mandates and checkouts

| Pairing | Request | Inputs |
| --- | --- | --- |
| `ap2/checkout-mandate` | `ap2-checkout-mandate` | none |
| `ucp/checkout/ap2-mandate` | `ucp-checkout` | none |
| `ucp/booking/ap2-mandate` | `ucp-checkout` | none |
| `ucp/checkout/unsigned` | none | none |
| `ucp/booking/unsigned` | none | none |
| `acp/checkout/delegated` | `acp-allowance` | `max_amount` (integer, minor units), `currency` (string), `merchant_id` (string), `expires_at` (string) |
| `acp/checkout/undelegated` | none | none |
| `ack/payment-request` | none | none |

Where the request is "none", `confirm` returns `request: null` and `transact` returns `signed: null` once the
comparison and, where the pairing needs one, the agreement payment are done. The protocol's own flow completes the
payment.

## Pairings that pay an agreement first

Every pairing whose payment is not itself a public proof of H pays the seller's agreement URL first. The
[pairings reference](../reference/pairings.md) marks them, and the
[agreement payments guide](./agreement-payments.md) describes the exchange. Pass `agreementSigner` to `transact` when a
different wallet pays the agreement, for example an EVM wallet beside a card.
