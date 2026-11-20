---
title: Rails
description: What each rail needs from the buyer — the account form, the signing request, and the inputs the build reads.
---

Most pairings need nothing from you beyond the seller's document and your signer. Where a build needs a value only the
buyer can supply (a recent blockhash, an account sequence, a deposit), you pass it in `inputs`. This page lists, rail by
rail, the account form each pairing accepts, the kind of request your signer receives, and every input the build reads.
In `transact`, every request is shown to your approver with its summary before it is signed, and held to the pairing's
ceiling. `confirm` and `agree` compute the summary and hold the ceiling, but call no approver. `within` does neither
for a voucher, which signs no deadline of its own and pays only from the deposit of its opening, which the gate holds
to both when it builds it
(see [Pay with the gate](./pay-with-the-gate.md#ceilings-and-floors)). A few inputs below exist for the ceiling alone.

A missing or malformed input declines with `no-payable-option` and a detail ending in `/input-missing`, before any
fetch of the ATR, except the inputs read at the ceiling check (`ledgerIndex`, `currentSlot`, `currentEpoch`), which
decline after the hash is compared and before anything is signed, and a missing floor input, which declines
`floor-missing`. Input values are JSON: a **decimal** is a string of digits (`"1000000"`), an **integer** is a JSON
number, **hex** is `0x` followed by hex digits.

The [pairings reference](../reference/pairings.md) gives each pairing's binding export, its Python constant, and what
its payment proves. The [signers guide](./signers.md) gives the answer each request kind takes.

## Accounts

The signer's `account` is CAIP-10. Its namespace selects the pairings it can pay:

| Namespace | Rails | Example |
| --- | --- | --- |
| `eip155` | EVM chains, Tempo, and MPP's EVM, Tempo and `usdc/evm` pairings | `eip155:84532:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266` |
| `solana` | Solana | `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:<base58 address>` |
| `stellar`, `xrpl`, `hedera`, `algorand`, `aptos`, `sui`, `near`, `starknet`, `polkadot`, `tron`, `tvm`, `cardano`, `casper`, `ccd`, `stacks` | The chain of that name (`tvm` is TON, `ccd` is Concordium) | `<namespace>:<network>:<address>` |
| `lnbtc` | Lightning (`x402/exact/lnbtc/payment-hash`, and MPP's Lightning pairings) | `lnbtc:000000000019d6689c085ae165831e93:<node id>` |
| `cloudflare` | `x402/batch-settlement/cloudflare`, where the account names your agent | `cloudflare:402:agent.example` |
| any | Card, AP2, UCP, ACP and ACK pairings, where the account names the buyer; MPP's card and Stripe pairings, which do not read it; `mpp/charge/nearintents`, on the challenge's origin network; `mpp/charge/usdc/gateway`, on a network the challenge accepts as a Gateway source | |

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
| `x402/batch-settlement/eip155` | `batch` of two `eip712`: the opening's token authorization, then the first voucher | `payerAuthorizer` (address, required); `deposit` (decimal, required unless the option's `extra.minDeposit` sets it); `authSalt` (32-byte hex, optional: drawn at random otherwise) |
| `mpp/charge/evm/authorization` | `eip712` | `tokenDomain` (object, required: the token's EIP-712 `name` and `version`) |
| `mpp/charge/evm/permit2` | `eip712` | `spender` (string, required: the seller server's submitting address) |
| `mpp/charge/evm/transaction` | `evm-call` | none |
| `mpp/charge/evm/hash` | `evm-call`, broadcast by the signer | none |
| `mpp/charge/usdc/evm` | `eip712` | `tokenDomain` (object, required) |
| `mpp/charge/usdc/gateway` | `gateway-burn-intent`: the salt's preimage, the `maxBlockHeight` the build computed and the challenge's `request` as issued; the buyer's Gateway client computes the salt and signs the burn intent | the floor inputs, required: `sourceNetwork` (string: the CAIP-2 network the burn intent spends from), `burnIntentExpirationHeight` (decimal string: what Circle Gateway's `GET /v1/info` serves for that network) and `withdrawalDelay` (decimal string: that network's Gateway Wallet's `withdrawalDelay()`, in blocks) |
| `x402/exact/eip155/gateway-batched` | `eip712`: an EIP-3009 `TransferWithAuthorization` under the Gateway Wallet's `GatewayWalletBatched` domain, with H as its nonce, which Circle Gateway settles in batches; no public ledger shows it, so the agreement is paid first, on the payment's own network | the floor input, required: `minValiditySeconds` (positive integer: what Circle Gateway's `/supported` serves for the network) |
| `mpp/session/evm` | two steps: the funding (`eip712`, a transfer authorization or a Permit2 transfer), then the first voucher (`eip712`) | `deposit` (decimal, required); `authorizedSigner` (address, optional); `credentialType` (`authorization` or `permit2`, optional); `tokenDomain` (object, optional) |
| `spend-permissions/eip155` | the account's approval of a Spend Permission whose `salt` is H, the sale's agreement and never a charge: `eip712`, the permission's typed data, where the offer accepts the route `"signature"`; otherwise `evm-call` with `broadcast: true`, the manager's `approve` call, which the account sends itself | none |

## Tempo

| Pairing | Request | Inputs |
| --- | --- | --- |
| `mpp/charge/tempo/split-memo` | none: the resource server places H as the memo of a one-unit split in the challenge, and your stock MPP client builds and signs the Tempo transaction from it, which the server's settler broadcasts | none |
| `mpp/charge/tempo/split-memo/push` | none, as above; your client broadcasts the transaction and names it by its hash | none; pass `check` the landed receipt your own reader read for it |
| `mpp/session/tempo` | two steps: the signed open transaction (`tempo-call`), then the first voucher (`eip712`) | `deposit` (decimal, required); `authorizedSigner`, `credentialType`, `tokenDomain` (optional) |
| `mpp/subscription/tempo` | `tempo-key-authorization` | none |

On both split-memo pairings the gate compares the ATR and hands nothing to the signer; `check` reads H from the
transaction your client signed.

## Solana

| Pairing | Request | Inputs |
| --- | --- | --- |
| `x402/exact/solana` | `solana-message` | `decimals` (integer) and `tokenProgram` (string): the mint's; `recentBlockhash` (string, required unless the option's `extra.recentBlockhash` is a base58 key of 32 bytes); `computeUnitLimit` (integer, optional); `computeUnitPrice` (decimal, optional) |
| `x402/upto/solana` | `solana-message` | `openSlot` (decimal), `tokenProgram` (string), `recentBlockhash` (string); `nonce` (decimal, optional: a random u64 otherwise); `computeUnitLimit`, `computeUnitPrice` (optional) |
| `x402/batch-settlement/solana` | `batch`: the opening's `solana-message`, then the first voucher's `ed25519-raw`, shown with the voucher's amount, the `open`'s distribution, deposit and mint | `payerAuthorizer` (string), `openSlot` (decimal), `tokenProgram` (string); `recentBlockhash` (unless the option names one); `deposit` (unless `extra.minDeposit` sets it); `salt`, `computeUnitLimit`, `computeUnitPrice` (optional) |
| `mpp/charge/solana` | `solana-message` | `decimals`, `tokenProgram`, `recentBlockhash`, each required only where the request's `methodDetails` leaves it out (none for native SOL besides the blockhash); `computeUnitLimit`, `computeUnitPrice` (optional) |
| `mpp/charge/solana/unsponsored` | `solana-message`, the payer being the message's fee payer | as `mpp/charge/solana` |
| `mpp/charge/usdc/solana` | `solana-message` | as `mpp/charge/solana`, read from `methodDetails.solana` |
| `mpp/subscription/solana` | none: your stock `@solana/mpp` client composes and signs the activation, writing H's LCP string as its Memo instruction, and the seller's server co-signs and submits it | none |
| `mpp/session/solana/memo` | `solana-session-open`: the message of the payment channel's `open`, with one Memo instruction carrying H's LCP string, which the payer signs once; the seller's server co-signs it as the challenge's `operator` and submits it. terms builds none of the session's vouchers: sign the 50 bytes the protocol package's `solanaVoucher` writes yourself | `salt` (decimal, optional: a random u64 otherwise); `authorizedSigner` (base58 address, optional: the payer's own key otherwise); `deposit` (decimal, optional: the request's `cap` otherwise); `gracePeriod` (integer, optional); `openSlot`, `recentBlockhash`, `mint`, `tokenProgram` (each optional, where the request leaves it out) |
| `mpp/session/solana/stock` | none: your stock client composes, signs and broadcasts the `open` itself, with a random salt; agreement first, on the session's own network, from the account that opens it | none |

## Stellar

| Pairing | Request | Inputs |
| --- | --- | --- |
| `x402/exact/stellar/precondition` | `stellar-precondition`: the Soroban authorization's `preimage`, whose SHA-256 your key signs, and the 40-byte `payload` of the signed-payload precondition, H then the entry's nonce, which your key signs raw. It is the sale's agreement on Stellar, never a charge | `simulatedXdr` (string: your simulated `transfer(you, payTo, amount)` transaction), `currentLedger` (integer: the ledger you read, from which the authorization's expiration and the payment's window are counted) |

The gate passes your account's address to the build as the payer, and the build holds the `transfer` your simulated
transaction carries to the option before anything reaches your signer.

## XRP Ledger

| Pairing | Request | Inputs |
| --- | --- | --- |
| `x402/exact/xrpl` | `xrpl-tx` | `fee` (decimal), `lastLedgerSequence` (integer), and `sequence` (integer) or, where the option's `extra.assetTransferMethod` is `ticketSequence`, `ticketSequence` (integer); `ledgerIndex` (integer) |
| `x402/upto/xrpl` | none: your own client opens the payment channel and signs its claim, neither carrying H; agreement first, on the option's own network, from the account that opens the channel | none |
| `mpp/charge/xrpl` | `xrpl-tx` | `fee` (decimal), `sequence` (integer), `lastLedgerSequence` (integer); `ledgerIndex` (integer) |
| `mpp/session/xrpl` | `xrpl-session-open` | `deposit` (decimal) and `xrpl` (object): `publicKey` (hex), `settleDelay` (integer), `fee` (decimal), `sequence` (integer), `lastLedgerSequence` (integer), `cancelAfter` (integer, optional); `ledgerIndex` (integer) |
| `mpp/session/xrpl/stock` | none: your stock client opens the channel itself, with no memo; agreement first, on the session's own network, from the account that opens it | none |

An XRPL transaction signs its deadline, `LastLedgerSequence`, and no start, so the gate counts the payment's window from
`ledgerIndex`, the index of the validated ledger you read (rippled's `ledger_index`), a non-negative integer, at five
seconds a ledger. A signing on the XRP Ledger without it, a payment or the agreement a pairing there follows, is
declined `no-payable-option` with `xrpl/input-missing`, after the hash is compared and before anything is signed.

An `mpp/session/xrpl` challenge's `amount` is the first claim's cumulative total in drops, which the claim signs as a
64-bit unsigned integer. A challenge whose `amount` is anything but such a number written as a decimal string, with no
sign, point or leading zero, does not offer the pairing (`mpp/request-malformed`): the gate declines
`no-payable-option`, and nothing is signed.

## Hedera

| Pairing | Request | Inputs |
| --- | --- | --- |
| `x402/exact/hedera` | `hedera-body` | `node` (string), `validStart` (object: `seconds` decimal, `nanos` integer), `maxFee` (decimal); `decimals` (integer, optional) |
| `x402/exact/hedera/transfer-executor` | `hedera-executor` | none |
| `mpp/charge/lcp/hedera` | `hedera-body`: the `TransactionBody` whose memo is H's LCP string, debiting your account alone, its transaction id naming the request's `feePayerAccountId` where its `feePayer` is true. The signer never broadcasts it: the party that submits sends the signed bytes unchanged | `node` (string), `validStart` (object: `seconds` decimal, `nanos` integer), `maxFee` (decimal); `decimals` (integer, optional) |
| `mpp/session/hedera/stock` | none: your stock client sends the escrow's `approve` and `open` itself, with a random salt; agreement first, on the session's own network, from the account that opens it | none |

## Other chains

| Pairing | Request | Inputs |
| --- | --- | --- |
| `x402/exact/algorand` | `algorand-txn` | `params` (object: algod's `firstValid` and `minFee` and `feePerByte` as decimals, `genesisHash`, `genesisId`) |
| `x402/exact/aptos` | `aptos-transaction`: the wallet builds and signs the scheme's payment, with an expiry no later than the request's `maxExpirationTimestampSecs`. An answer that is not an object whose `transaction` is a string is declined `signed-not-bound` (`x402/signature-malformed`). The transaction is read as the seller's `reference` reads it, and declined `signed-not-bound` with `reference`'s code for each fault: text that is not base64 of a transaction prefix that reads to the end of its fields, or that names a module, function or struct with a name that is not a Move identifier, `aptos/tx-malformed`; a transaction over 64 KiB decoded, `aptos/tx-too-large`; a payload that is not an entry function call, `aptos/not-entry-function`; a call that is not the framework `primary_fungible_store::transfer` or `fungible_asset::transfer` with one struct type argument and three arguments, `aptos/not-an-x402-transfer`; and a transaction for a chain other than the option's network, `aptos/chain-mismatch` | none |
| `x402/exact/sui` | `sui-transaction`: the wallet builds the payment, with an expiration epoch no later than the request's `maxEpoch`, and adds the request's `pureInput` | `currentEpoch` (integer: the epoch you read) |
| `x402/exact/near` | `near-delegate` | `publicKey` (string), `accessKeyNonce` (decimal), `finalHeight` (decimal): from your RPC |
| `mpp/charge/nearintents` | none: the comparison is the buyer's whole step | none |
| `x402/exact/starknet` | `starknet-snip12` | none |
| `x402/exact/polkadot/lcp-assets-remark` | `substrate-call`, with `maxEraPeriod`, the longest mortal era the wallet may sign | none |
| `x402/exact/tron/lcp-trc20-memo` | `tron-txid` | `refBlock` (object: `{ number, id }` of a recent block), `feeLimit` (decimal) |
| `x402/exact/tvm` | `ton-w5` | `walletId` (integer), `seqno` (integer), `jettonWallet` (string), `attachNanotons` (decimal); `stateInit` (base64 BoC, for a wallet not yet deployed) |
| `x402/exact/cardano` | `cardano-transaction`, with `maxTtl`, the latest TTL the wallet may set | `currentSlot` (integer: the slot you read) |
| `x402/exact/cardano/lock` | `cardano-transaction` for a lock, a charge and never an agreement: `extra.assetTransferMethod` `"script"`, a deposit into a contract the seller defines, shown with `payTo` as its payee; or `"masumi"`, a deposit into the escrow every seller of a deployment shares, shown with the seller its `extra.terms.sellerAddress` names as its payee and the escrow, `payTo`, as `grant` | `currentSlot` (integer) |
| `x402/exact/casper` | `casper-eip712` | none |
| `x402/exact/ccd` | `ccd-transfer` | none |
| `mpp/charge/usdc/stacks` | `stacks-contract-call` | none |

The gate builds `x402/exact/casper` and `x402/exact/ccd` exactly as their profiles define them, but neither is
confirmed in the protocol package's registry: nothing outside the protocol package has yet shown either form, and the
stock clients do not build it (the stock Casper client draws a random nonce, and the stock Concordium client writes no
memo).

## Lightning

| Pairing | Request | Inputs |
| --- | --- | --- |
| `x402/exact/lnbtc/payment-hash` | `bolt11-pay`: the invoice the seller's node issued, after the agreement, for the payment hash the ATR commits (`extra.paymentHash`); agreement first | `request` (object, required): the request you mean to make, from which the build computes the scheme's request hash and holds the invoice's `h` to it. Over HTTP `{ profile: "http:1", method, url, body?, headers? }`, `url` the absolute URL, `body` the content bytes as `0x` hex; over MCP `{ profile: "mcp:1", server, name, arguments?, meta? }`. |
| `mpp/charge/lightning` | `bolt11-pay` | none |
| `mpp/session/lightning` | `bolt11-pay` for the deposit invoice | `returnInvoice` (string, required) |

Your node moves the payment when it pays the invoice. A decline after that carries `moved`.

On `x402/exact/lnbtc/payment-hash` the build makes the client's checks of the option and its invoice before it hands
the invoice over: the invoice's `p` is the committed hash, its `h` the request hash of your `request`, its signer
`payTo`, its currency the network's, its amount `amount` and its expiry `maxTimeoutSeconds`, and it is unexpired. The
payer signs nothing that carries H; the proof is the agreement payment, paid first. `request` here is the scheme's own
form, read by the build; it is not the gate's `resourceRequest`, which you pass as well.

## Cloudflare

| Pairing | Request | Inputs |
| --- | --- | --- |
| `x402/batch-settlement/cloudflare` | none: the build is the payment, and your agent's HTTP message signature signs the request that carries it | none |

## Cards and Stripe

| Pairing | Request | Inputs |
| --- | --- | --- |
| `card/visa-tap` | `tap-field`: the nonce for the agent's TAP message signatures, whose first 32 bytes are H | none |
| `card/mastercard-agent-pay` | `tap-field`: the nonce for the agent's Agent Pay message signatures | none |
| `card/visa-vic` | `vic-reference`: the transaction reference the agent writes into its Visa Intelligent Commerce credential request | none |
| `card/mastercard-vi/immediate` | `vi-checkout-mandate` (the user's L2), over the seller's `checkout_jwt`; or, where the seller serves no `checkout_jwt`, two steps: `vi-checkout`, your checkout payload with the seller's `legalContext` written into it, for the agent to sign as its `checkout_jwt`, then `vi-checkout-mandate` over it | `checkout` (object: the agent's checkout payload), required where the seller serves no `checkout_jwt` |
| `card/mastercard-vi/autonomous` | `vi-checkout-mandate` (the agent's L3b) | none |
| `card/seller-reference` | none: the comparison is the buyer's whole step | none |
| `mpp/charge/card` | none | none |
| `mpp/charge/stripe` | none | none |
| `mpp/subscription/stripe` | none | none |

## Mandates and checkouts

| Pairing | Request | Inputs |
| --- | --- | --- |
| `ap2/checkout-mandate` | `ap2-checkout-mandate` | none |
| `ap2/checkout-mandate/x402` | `ap2-checkout-mandate`, as above; the x402 payment is your own credential provider's, which carries no H | none |
| `ucp/checkout/ap2-mandate` | `ucp-checkout` | none |
| `ucp/booking/ap2-mandate` | `ucp-checkout` | none |
| `ucp/checkout/unsigned` | none | none |
| `ucp/checkout/agent-signed` | `ucp-legal-context`: the `legal_context` member the platform writes into the request that completes the checkout, beside the checkout | none |
| `ucp/booking/unsigned` | none | none |
| `acp/checkout/delegated` | `acp-allowance` | `max_amount` (integer, minor units), `currency` (string), `merchant_id` (string), `expires_at` (string) |
| `acp/checkout/undelegated` | none | none |
| `ack/payment-request` | none | none |

Every card pairing that hands the signer a request (all but `card/seller-reference`) signs no end, so `transact` and
`confirm` decline it `no-end` until `ceilings` maps its pairing to `"no-end"`.

Where the request is "none", `confirm` returns `request: null`. For `x402/batch-settlement/cloudflare`, whose build is
itself the payment, `finish` with a `null` signature completes it, and `transact` returns it as `signed`. For every
other such pairing, `transact` returns `signed: null` once the comparison and, where the pairing needs one, the
agreement payment are done, and the protocol's own flow completes the payment.

## Pairings that pay an agreement first

With `transact`, every pairing at coverage `none` pays the seller's agreement URL first, once the buyer's agent and
your approver have approved that payment, on any network or on the payment's own network as the pairing's
`agreementOn` says. `confirm` and `finish` neither pay nor check the agreement; only
`transact` and `agree` do (see [driving the steps yourself](./agreement-payments.md#driving-the-steps-yourself)). The
[pairings reference](../reference/pairings.md) marks these pairings, and the
[agreement payments guide](./agreement-payments.md) describes the exchange. The agreement payment's build reads the
same `inputs` as the payment's own: a Solana agreement option reads the Solana inputs above. Pass `agreementSigner` to
`transact` when a different wallet pays the agreement, for example an EVM wallet beside a card.
