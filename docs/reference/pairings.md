---
title: Pairings
description: Every pairing the gate pays, with its coverage, whether it is confirmed, its agreement, its imports in each language, and what its payment proves.
---

The gate serves 77 pairings, in TypeScript and in Python alike. This page is generated from the code:
`node scripts/docs.mjs generate` writes it from `BINDINGS` in `@integraledger/lcp` and the pairings the gate serves,
and `node scripts/docs.mjs check` fails when it differs from them or from the Python package's bindings.

Columns, each read from the pairing's registry data (`data`) in `@integraledger/lcp`, and the last also from the
gate's own rule:

- **Coverage**: `full` where the payment is itself a public proof of H, the payer's own signed act on a public
  ledger binding all of H; `none` otherwise (see [Concepts](../concepts.md#coverage)).
- **Confirmed**: `yes` where something outside the protocol package has shown the form as its profile defines it
  (`confirmed`); `no` otherwise. The gate builds and reads a pairing at `no` exactly as its profile defines it,
  though nothing outside the protocol package has yet shown that form.
- **Agreement payment first**: whether the gate pays the seller's agreement payment before this payment, and on
  which network that agreement may be (`agreementOn`): any network, or only the payment's own (see
  [Agreement payments](../guides/agreement-payments.md)).
- **Pays an agreement**: what the gate does with this pairing's payment as an agreement. `yes`: the gate pays,
  through this pairing, the agreement payment another pairing follows (`transact` and `agree`), and the payment can
  also be a charge; these are x402 pairings whose registry data holds an agreement form (`agreement`). `only`: the
  payment is never a charge, only an agreement (`agreement.only`): `transact` declines it as a charge, the approver
  is asked about each of its signings as the act `agreement`, and on an x402 pairing the gate pays it as the
  agreement another pairing follows.
  `no`: the gate pays no agreement through it. The gate pays an agreement only through x402 pairings: an MPP pairing
  whose registry data holds `agreement` reads `no`, and the gate returns the seller's MPP agreement challenges as
  `agreementChallenges`, for your own MPP client to pay.

Below each table, every pairing's statement of what its payment proves, as its registry data states it
(`data.proves`). Where a statement names `<network>` and `<transaction>`, they stand for the agreement payment's
network and transaction.

## EVM

| Pairing | Coverage | Confirmed | Agreement payment first | Pays an agreement | TypeScript | Python |
| --- | --- | --- | --- | --- | --- | --- |
| `mpp/charge/evm/authorization` | full | yes | no | no | `evmAuthorization` from `@integraledger/lcp/mpp` | `MPP_CHARGE_EVM_AUTHORIZATION` |
| `mpp/charge/evm/hash` | none | no | yes, any network | no | `evmHash` from `@integraledger/lcp/mpp` | `MPP_CHARGE_EVM_HASH` |
| `mpp/charge/evm/permit2` | full | no | no | no | `evmPermit2` from `@integraledger/lcp/mpp` | `MPP_CHARGE_EVM_PERMIT2` |
| `mpp/charge/evm/transaction` | none | no | yes, any network | no | `evmTransaction` from `@integraledger/lcp/mpp` | `MPP_CHARGE_EVM_TRANSACTION` |
| `mpp/charge/usdc/evm` | full | no | no | no | `chargeUsdcEvm` from `@integraledger/lcp/mpp` | `MPP_CHARGE_USDC_EVM` |
| `mpp/charge/usdc/gateway` | none | no | yes, any network | no | `chargeUsdcGateway` from `@integraledger/lcp/mpp` | `MPP_CHARGE_USDC_GATEWAY` |
| `mpp/session/evm` | full | no | no | no | `sessionEvm` from `@integraledger/lcp/mpp` | `MPP_SESSION_EVM` |
| `spend-permissions/eip155` | full | yes | no | only | `spendPermissionsEip155` from `@integraledger/lcp/spend-permissions` | `SPEND_PERMISSIONS_EIP155` |
| `x402/auth-capture/eip155/eip3009` | full | no | no | no | `authCaptureEip3009` from `@integraledger/lcp/x402` | `X402_AUTH_CAPTURE_EIP155_EIP3009` |
| `x402/auth-capture/eip155/permit2` | full | no | no | no | `authCapturePermit2` from `@integraledger/lcp/x402` | `X402_AUTH_CAPTURE_EIP155_PERMIT2` |
| `x402/batch-settlement/eip155` | full | no | no | no | `batchEvm` from `@integraledger/lcp/x402-batch-settlement` | `X402_BATCH_SETTLEMENT_EIP155` |
| `x402/exact/eip155/eip3009` | full | yes | no | yes | `exactEip3009` from `@integraledger/lcp/x402` | `X402_EXACT_EIP155_EIP3009` |
| `x402/exact/eip155/erc7710` | none | no | yes, any network | no | `exactErc7710` from `@integraledger/lcp/x402` | `X402_EXACT_EIP155_ERC7710` |
| `x402/exact/eip155/erc7710-salt` | full | no | no | no | `exactErc7710Salt` from `@integraledger/lcp/x402` | `X402_EXACT_EIP155_ERC7710_SALT` |
| `x402/exact/eip155/gateway-batched` | none | yes | yes, its network | no | `exactGatewayBatched` from `@integraledger/lcp/x402` | `X402_EXACT_EIP155_GATEWAY_BATCHED` |
| `x402/exact/eip155/permit2` | full | no | no | yes | `exactPermit2` from `@integraledger/lcp/x402` | `X402_EXACT_EIP155_PERMIT2` |
| `x402/upto/eip155/permit2` | full | no | no | no | `uptoPermit2` from `@integraledger/lcp/x402` | `X402_UPTO_EIP155_PERMIT2` |

**`mpp/charge/evm/authorization`**: The payer signed an EIP-3009 transfer authorization whose nonce is keccak256 of this challenge's id and realm, and the id is this ATR's hash in base64url with the challenge's position. The token contract verified the signature when it executed the transfer, and the nonce is on chain as the nonce topic of its AuthorizationUsed event. A holder of the ATR and the realm can confirm the hash from that nonce; the chain alone does not reveal it. This does not show that amount, payee, asset or timing match the ATR's content.

**`mpp/charge/evm/hash`**: Before this payment, an account signed an agreement carrying this ATR's hash on \<network>, recorded in \<transaction>; that shows neither that the account is the payer nor when this charge was taken. The payment is an ERC-20 transfer signed as a whole transaction (`transaction`), or broadcast by its signer and named by its hash (`hash`), answering a challenge whose id and opaque carry this ATR's hash. The payment transaction does not carry the hash; the read found that the named transaction succeeded and moved a token to the challenge's recipient. This does not show that amount, payee, asset or timing match the ATR's content.

**`mpp/charge/evm/permit2`**: The payer signed a Permit2 transfer, single or batch, whose witness carries keccak256 of this challenge's id and realm, and the id is this ATR's hash in base64url with the challenge's position. Permit2 verified the signature when it executed the transfer; a batch's transfers all executed in that one call. The witness is in the settlement transaction's calldata only as a hash, and no event carries it. This does not show that amount, payee, asset, splits or timing match the ATR's content.

**`mpp/charge/evm/transaction`**: Before this payment, an account signed an agreement carrying this ATR's hash on \<network>, recorded in \<transaction>; that shows neither that the account is the payer nor when this charge was taken. The payment is an ERC-20 transfer signed as a whole transaction (`transaction`), or broadcast by its signer and named by its hash (`hash`), answering a challenge whose id and opaque carry this ATR's hash. The payment transaction does not carry the hash; the read found that the named transaction succeeded and moved a token to the challenge's recipient. This does not show that amount, payee, asset or timing match the ATR's content.

**`mpp/charge/usdc/evm`**: The payer signed an EIP-3009 authorization whose nonce is keccak256 of the JCS of this challenge's id, realm and request hash, and the id is this ATR's hash in base64url with the challenge's position. The token contract verified the signature when it executed the transfer, and the nonce is on chain in its AuthorizationUsed event. A holder of the ATR, the realm and the request can confirm the hash; the chain alone does not reveal it. This does not show that amount, payee, asset or timing match the ATR's content.

**`mpp/charge/usdc/gateway`**: The payer signed a Circle Gateway burn intent whose TransferSpec salt is keccak256 of the JCS of this challenge's id and parameters, and the id is this ATR's hash in base64url with the challenge's position. The signature is not verified here. The salt travels inside the TransferSpec that the destination mint carries, and the Gateway Minter emits that TransferSpec's keccak256 hash; this record reads no chain, and settlement is the seller's report. This does not show that amount, payee, asset or timing match the ATR's content.

**`mpp/session/evm`**: The ATR's hash is in the MPP session challenge this channel opened under: its id is the hash in base64url with the challenge's position. The payer opened a payment channel whose salt is this ATR's hash, so the channel id, keccak256 over the payer, payee, token, salt, authorized signer, escrow and chain, commits to it. The payer signed that opening as an open call carrying the salt, an EIP-3009 authorization whose nonce is MPP's hash over the channel parameters and the salt, or a Permit2 transfer whose witness carries the salt. The seller read that the opening transaction succeeded and moved the payer's deposit to the escrow, and that the escrow ran the open call as the transaction shows it: an `openWithAuthorization` by its token's AuthorizationUsed of the payer and the nonce the escrow recomputes over the channel parameters and the salt, or an `openWithPermit2` as the transaction's own call to the escrow. Its salt is this ATR's hash, its payee is the channel's beneficiary, and the payer is the account its authorization or permit is signed by, whose deposit moved to the escrow. This does not show that amount, payee, asset or timing match the ATR's content. Each voucher in this channel signs a commitment to this ATR's hash.

**`spend-permissions/eip155`**: The account named signed a Spend Permission whose salt is this ATR's hash, naming the payee as spender, and the SpendPermissionManager approved it: the hash is on chain in the permission its SpendPermissionApproved event carries in the approval's transaction. The approval moves nothing. This does not show that any amount was later spent, nor that the allowance, period, token or timing match the ATR's content.

**`x402/auth-capture/eip155/eip3009`**: The payer signed a token authorization whose nonce commits, through the escrow's PaymentInfo, to a salt that is this ATR's hash when unbound, or a commitment over it with the receiver authorizer and policy when bound. The token contract verified the signature when the escrow collected the payment, and the escrow's event carries the salt. When unbound, the salt is this ATR's hash, so the settled transaction itself shows it. When bound, a holder of the ATR, the receiver authorizer and the policy can confirm the hash from the salt; the chain alone does not reveal it. This record covers that first collection; capture, void, refund and reclaim are the operator's and the payer's.

**`x402/auth-capture/eip155/permit2`**: The payment presented a Permit2 authorization whose nonce commits, through the escrow's PaymentInfo, to a salt that is this ATR's hash when unbound, or a commitment over it with the receiver authorizer and policy when bound. The escrow's event in the settlement transaction carries that PaymentInfo, salt included, and names the deployment's Permit2 collector as the token collector that funded it. When unbound, the salt is this ATR's hash, so the settled transaction itself shows it. When bound, a holder of the ATR, the receiver authorizer and the policy can confirm the hash from the salt; the chain alone does not reveal it. This record covers that first collection; capture, void, refund and reclaim are the operator's and the payer's.

**`x402/batch-settlement/eip155`**: The payer signed a token authorization for a deposit into an x402 batch-settlement channel whose identifier, the EIP-712 hash of the channel's configuration, commits to this ATR's hash as the configuration's salt, or, in the scheme's refund-authorizer mode, whose own salt is this ATR's hash. The token contract or Permit2 verified that signature when the channel contract collected the deposit, and the hash is on chain as the salt in the channel's ChannelCreated event, or in that mode in the deposit call. Each voucher in this channel signs a commitment to the channel, and so, outside that mode, to this ATR's hash. This does not show that amount, payee, asset or timing match the ATR's content.

**`x402/exact/eip155/eip3009`**: The payer signed an EIP-3009 transfer authorization whose nonce is this ATR's hash, or for an agreement the agreement's value of it. The token contract verified that signature when it executed the transfer, and the hash is on chain as the nonce topic of its AuthorizationUsed event in the settlement transaction. This does not show that amount, payee, asset or timing match the ATR's content.

**`x402/exact/eip155/erc7710`**: Before this payment was taken, an account signed an agreement transaction carrying this ATR's hash on \<network>, recorded in \<transaction>; this shows neither that the account is the payer nor what the agreement moved. The ATR was assembled and delivered before the payment, and the payment payload echoed this ATR's hash in the legalContext entry of x402's extensions. The read found the named settlement transaction, after the agreement's position, holding a transfer from the payment's delegator to the payee. The delegation does not sign the hash, and the settlement transaction does not carry it.

**`x402/exact/eip155/erc7710-salt`**: The leaf delegation of the permission context redeemed for this payment, made through MetaMask's DelegationManager, carries this ATR's hash as its signed salt. The manager verified every delegation's signature when it redeemed them, and the leaf, with its salt, is in a RedeemedDelegation event in the settlement transaction. The leaf's signer is its delegator, which may be an account the paying account authorised rather than the paying account itself. This does not show that amount, payee, asset or timing match the ATR's content.

**`x402/exact/eip155/gateway-batched`**: Before this payment was reported, an account signed an agreement transaction carrying this ATR's hash on \<network>, recorded in \<transaction>; this shows neither that the account is the payer nor when the payment was taken. The payment presented was a Circle Gateway batched authorization whose nonce is this ATR's hash, signed under the Gateway Wallet's domain; no public ledger records it, since a batch carries each depositor's net change and no payment's nonce, and Circle's transfers API listing it by its nonce is Circle's statement, not a ledger's. The seller reported it paid. This does not show that amount, payee, asset or timing match the ATR's content.

**`x402/exact/eip155/permit2`**: The payer signed a Permit2 witness transfer whose nonce is this ATR's hash, or for an agreement the agreement's value of it, with the scheme's x402 proxy as spender and the payee in the witness. Permit2 verified the signature when the proxy executed the transfer, and the hash is in the settlement transaction's calldata as the Permit2 nonce; no event carries it. This does not show that amount, payee, asset or timing match the ATR's content.

**`x402/upto/eip155/permit2`**: The payer signed a Permit2 witness transfer whose nonce is this ATR's hash, with the scheme's x402 proxy as spender and the payee in the witness. Permit2 verified the signature when the proxy executed the transfer, and the hash is in the settlement transaction's calldata as the Permit2 nonce; no event carries it. This does not show that amount, payee, asset or timing match the ATR's content. The amount settled is the seller's, submitted by the facilitator the witness names, and at most the signed maximum.

## Tempo

| Pairing | Coverage | Confirmed | Agreement payment first | Pays an agreement | TypeScript | Python |
| --- | --- | --- | --- | --- | --- | --- |
| `mpp/charge/tempo/split-memo` | full | yes | no | no | `tempoSplitMemo` from `@integraledger/lcp/mpp` | `MPP_CHARGE_TEMPO_SPLIT_MEMO` |
| `mpp/charge/tempo/split-memo/push` | full | no | no | no | `tempoSplitMemoPush` from `@integraledger/lcp/mpp` | `MPP_CHARGE_TEMPO_SPLIT_MEMO_PUSH` |
| `mpp/session/tempo` | full | no | no | no | `sessionTempo` from `@integraledger/lcp/mpp` | `MPP_SESSION_TEMPO` |
| `mpp/subscription/tempo` | full | no | no | no | `subscriptionTempo` from `@integraledger/lcp/mpp` | `MPP_SUBSCRIPTION_TEMPO` |

**`mpp/charge/tempo/split-memo`**: The ATR's hash is in the MPP Tempo charge challenge the payer answered: its id is the hash in base64url with the challenge's position, and one of its splits carries the hash as its memo. The payer's own signed Tempo transaction carries all of the hash as the memo of a `transferWithMemo` call, and the chain verified the payer's signature when it executed the call. The record states "paid" where value moved, with the account it reached, and "signed" where nothing moved. This does not show that amount, payee, asset or timing match the ATR's content.

**`mpp/charge/tempo/split-memo/push`**: The ATR's hash is in the MPP Tempo charge challenge the payer answered: its id is the hash in base64url with the challenge's position, and one of its splits carries the hash as its memo. The payer's own signed Tempo transaction carries all of the hash as the memo of a `transferWithMemo` call, and the chain verified the payer's signature when it executed the call. The record states "paid" where value moved, with the account it reached, and "signed" where nothing moved. This does not show that amount, payee, asset or timing match the ATR's content.

**`mpp/session/tempo`**: The ATR's hash is in the MPP session challenge this channel opened under: its id is the hash in base64url with the challenge's position. The payer signed a Tempo transaction whose one call to the channel escrow opens a channel with this ATR's hash as its salt, and the chain verified that signature when it executed the call. The escrow's ChannelOpened event names the channel, whose id commits to the salt, and carries the salt itself, on the v1 escrow as on the TIP-1034 escrow. This does not show that amount, payee, asset or timing match the ATR's content. Each voucher in this channel signs a commitment to this ATR's hash.

**`mpp/subscription/tempo`**: The ATR's hash is the MPP subscription challenge's id, in base64url. The payer's root key signed a Tempo key authorization whose witness is this ATR's hash, granting the seller's access key a per-period limit. The chain verified that signature when the activation transaction registered the key, and the account keychain's KeyAuthorizationWitness event carries the payer's account and this hash as topics. The key authorization names one recipient the key may pay; what the same transaction transferred from the payer's account, if anything, is recorded as what moved, with its recipient. This does not show that amount, period, payee, asset or timing match the ATR's content.

## Solana

| Pairing | Coverage | Confirmed | Agreement payment first | Pays an agreement | TypeScript | Python |
| --- | --- | --- | --- | --- | --- | --- |
| `mpp/charge/solana` | full | no | no | no | `chargeSolana` from `@integraledger/lcp/mpp` | `MPP_CHARGE_SOLANA` |
| `mpp/charge/solana/unsponsored` | full | no | no | no | `chargeSolanaUnsponsored` from `@integraledger/lcp/mpp` | `MPP_CHARGE_SOLANA_UNSPONSORED` |
| `mpp/charge/usdc/solana` | full | no | no | no | `chargeUsdcSolana` from `@integraledger/lcp/mpp` | `MPP_CHARGE_USDC_SOLANA` |
| `mpp/session/solana/memo` | full | no | no | no | `sessionSolanaMemo` from `@integraledger/lcp/mpp` | `MPP_SESSION_SOLANA_MEMO` |
| `mpp/session/solana/stock` | none | no | yes, its network | no | `sessionSolanaStock` from `@integraledger/lcp/mpp` | `MPP_SESSION_SOLANA_STOCK` |
| `mpp/subscription/solana` | full | no | no | no | `subscriptionSolana` from `@integraledger/lcp/mpp` | `MPP_SUBSCRIPTION_SOLANA` |
| `x402/batch-settlement/solana` | full | no | no | no | `batchSvm` from `@integraledger/lcp/x402-batch-settlement` | `X402_BATCH_SETTLEMENT_SOLANA` |
| `x402/exact/solana` | full | yes | no | yes | `exactSvm` from `@integraledger/lcp/x402-exact-solana` | `X402_EXACT_SOLANA` |
| `x402/upto/solana` | full | no | no | no | `uptoSvm` from `@integraledger/lcp/x402-upto-solana` | `X402_UPTO_SOLANA` |

**`mpp/charge/solana`**: The payer's own signed act carries this ATR's hash: a Solana transaction the buyer's account signed, whose one LCP-form Memo instruction is the hash's LCP string, final at `finalized` with no error. It paid each transfer it made from the buyer's account, recorded with its mint or lamports, amount and recipient, one of zero included, the recipient being the owner the transaction's token balances name; as a payment, one of them reached an account the option's payee owns. The memo is in the transaction's instruction data on chain. It compares no amount, mint or time with the ATR's terms.

**`mpp/charge/solana/unsponsored`**: The payer's own signed act carries this ATR's hash: a Solana transaction the buyer's account signed, whose one LCP-form Memo instruction is the hash's LCP string, final at `finalized` with no error. It paid each transfer it made from the buyer's account, recorded with its mint or lamports, amount and recipient, one of zero included, the recipient being the owner the transaction's token balances name; as a payment, one of them reached an account the option's payee owns. The memo is in the transaction's instruction data on chain. It compares no amount, mint or time with the ATR's terms.

**`mpp/charge/usdc/solana`**: The payer's own signed act carries this ATR's hash: a Solana transaction the buyer's account signed, whose one LCP-form Memo instruction is the hash's LCP string, final at `finalized` with no error. It paid each transfer it made from the buyer's account, recorded with its mint or lamports, amount and recipient, one of zero included, the recipient being the owner the transaction's token balances name; as a payment, one of them reached an account the option's payee owns. The memo is in the transaction's instruction data on chain. It compares no amount, mint or time with the ATR's terms.

**`mpp/session/solana/memo`**: The payer's own signed act carries this ATR's hash: a Solana transaction the buyer's account signed, whose one LCP-form Memo instruction in the `open` the seller's operator co-signed and submitted is the hash's LCP string, final at `finalized` with no error, which deposited the amount its `open` names into a payment channel whose distribution names the option's payee, recorded with its mint and amount. The memo is in the transaction's instruction data on chain. Vouchers and the close do not carry the hash. It compares no amount, mint or time with the ATR's terms.

**`mpp/session/solana/stock`**: Before this opening was taken, an account signed an agreement transaction carrying this ATR's hash on \<network>, recorded in \<transaction>. The opening, a stock MPP session's payment-channel open that its payer broadcast and that carries no hash, came after it and deposited the amount its `open` names into a channel whose distribution names the option's payee. This does not show that the account that signed the agreement is the opening's payer, nor that amount, recipient, mint or timing match the ATR's content.

**`mpp/subscription/solana`**: The payer's own signed act carries this ATR's hash: a Solana transaction the buyer's account signed, a subscription's activation, whose one LCP-form Memo instruction is the hash's LCP string, final at `finalized` with no error, which paid the first period to an account the option's payee owns, recorded with its mint and amount. The memo is in the transaction's instruction data on chain. Renewals are the seller's later pulls, which do not carry the hash. It compares no amount, mint, period or time with the ATR's terms.

**`x402/batch-settlement/solana`**: The payer's own signed act carries this ATR's hash: a Solana transaction the buyer's account signed, whose seller Memo instruction (`extra.memo`), beside the scheme's receiver-authorizer memo, is the hash's LCP string, final at `finalized` with no error, which deposited the amount its `open` names into a payment channel whose distribution names the option's payee, recorded with its mint and amount. The memo is in the transaction's instruction data on chain. It compares no amount, mint or time with the ATR's terms.

**`x402/exact/solana`**: The payer's own signed act carries this ATR's hash: a Solana transaction the buyer's account signed, whose one LCP-form Memo instruction is the hash's LCP string, final at `finalized` with no error. It paid each transfer it made from the buyer's account, recorded with its mint or lamports, amount and recipient, one of zero included, the recipient being the owner the transaction's token balances name; as a payment, one of them reached an account the option's payee owns. The memo is in the transaction's instruction data on chain. It compares no amount, mint or time with the ATR's terms.

**`x402/upto/solana`**: The payer's own signed act carries this ATR's hash: a Solana transaction the buyer's account signed, whose one Memo instruction is the hash's LCP string, final at `finalized` with no error, which deposited the amount its `open` names into a payment channel whose distribution names the option's payee, recorded with its mint and amount. The memo is in the transaction's instruction data on chain. The deposit is the signed maximum a one-request channel escrows; the amount charged from it, which may be zero, is the seller's metering, settled in a later transaction that does not carry the hash, and the rest returns to the payer. It compares no amount, mint or time with the ATR's terms.

## Stellar

| Pairing | Coverage | Confirmed | Agreement payment first | Pays an agreement | TypeScript | Python |
| --- | --- | --- | --- | --- | --- | --- |
| `x402/exact/stellar/precondition` | full | yes | no | only | `exactStellarPrecondition` from `@integraledger/lcp/x402-exact-stellar` | `X402_EXACT_STELLAR_PRECONDITION` |

**`x402/exact/stellar/precondition`**: Signed: the buyer's account signed a Soroban authorization of a transfer and the 40-byte payload of this ATR's hash and that authorization's nonce, carried as a signed-payload precondition of the transaction that consumed it, so the buyer's own signed act carries the hash. The transaction succeeded on the asset contract its event names; where the transfer moved a nonzero amount, it paid the account the event's to names. This states nothing of the amount, nor that the asset, the account reached or the time meet a term of the ATR.

## XRP Ledger

| Pairing | Coverage | Confirmed | Agreement payment first | Pays an agreement | TypeScript | Python |
| --- | --- | --- | --- | --- | --- | --- |
| `mpp/charge/xrpl` | full | no | no | no | `chargeXrpl` from `@integraledger/lcp/mpp` | `MPP_CHARGE_XRPL` |
| `mpp/session/xrpl` | full | no | no | no | `sessionXrpl` from `@integraledger/lcp/mpp` | `MPP_SESSION_XRPL` |
| `mpp/session/xrpl/stock` | none | no | yes, its network | no | `sessionXrplStock` from `@integraledger/lcp/mpp` | `MPP_SESSION_XRPL_STOCK` |
| `x402/exact/xrpl` | full | yes | no | yes | `exactXrpl` from `@integraledger/lcp/x402-exact-xrpl` | `X402_EXACT_XRPL` |
| `x402/upto/xrpl` | none | no | yes, its network | no | `uptoXrpl` from `@integraledger/lcp/x402-upto-xrpl` | `X402_UPTO_XRPL` |

**`mpp/charge/xrpl`**: The payer signed an XRPL Payment whose InvoiceID is this ATR's hash, and it is in a validated ledger with tesSUCCESS: it paid the amount meta.delivered_amount states to the account its Destination names. This does not show that amount, destination, asset or timing match the ATR's content.

**`mpp/session/xrpl`**: The payer signed an XRPL PaymentChannelCreate whose one LCP memo carries this ATR's hash, and it is in a validated ledger with tesSUCCESS: it deposited the create's Amount into a channel whose beneficiary is the account its Destination names. The memo is in the public transaction. Vouchers in this channel sign the channel id and an amount, not the hash. This does not show that amount, deposit, destination, settle delay or timing match the ATR's content.

**`mpp/session/xrpl/stock`**: Before this session, an account signed an agreement transaction carrying this ATR's hash on the session's XRPL network. The channel's create is in a validated ledger with tesSUCCESS: the account the voucher's source names deposited the create's Amount into the channel the voucher names, whose beneficiary is the account its Destination names, after the ledger the agreement was recorded at. The create does not carry the hash, and this does not show that the account that signed the agreement is the one that opened the channel unless the record compares the two. Vouchers sign the channel id and an amount, not the hash. This does not show that amount, deposit, destination, settle delay or timing match the ATR's content.

**`x402/exact/xrpl`**: The payer signed an XRPL Payment whose InvoiceID is the SHA-256 of this ATR's hash in LCP string form, and it is in a validated ledger with tesSUCCESS: it paid the amount meta.delivered_amount states to the account its Destination names. The hash can be confirmed from the ATR's bytes but not recovered from the ledger alone. This does not show that amount, destination, asset or timing match the ATR's content.

**`x402/upto/xrpl`**: Before this payment, an account signed an agreement transaction carrying this ATR's hash on the payment's XRPL network. The channel's create is in a validated ledger with tesSUCCESS: the account the payment's payer names deposited the create's Amount into the channel the payment names, whose beneficiary is the account its Destination names, after the ledger the agreement was recorded at. The create does not carry the hash, and this does not show that the account that signed the agreement is the one that opened the channel unless the record compares the two. The claim that closes the channel signs the channel id and an amount, not the hash, and is not read. This does not show that amount, deposit, destination, settle delay or timing match the ATR's content.

## Hedera

| Pairing | Coverage | Confirmed | Agreement payment first | Pays an agreement | TypeScript | Python |
| --- | --- | --- | --- | --- | --- | --- |
| `mpp/charge/lcp/hedera` | full | no | no | no | `chargeLcpHedera` from `@integraledger/lcp/mpp` | `MPP_CHARGE_LCP_HEDERA` |
| `mpp/session/hedera/stock` | none | no | yes, its network | no | `sessionHederaStock` from `@integraledger/lcp/mpp` | `MPP_SESSION_HEDERA_STOCK` |
| `x402/exact/hedera` | full | yes | no | yes | `exactHedera` from `@integraledger/lcp/hedera` | `X402_EXACT_HEDERA` |
| `x402/exact/hedera/transfer-executor` | none | no | yes, any network | no | `exactHederaExecutor` from `@integraledger/lcp/hedera` | `X402_EXACT_HEDERA_TRANSFER_EXECUTOR` |

**`mpp/charge/lcp/hedera`**: The payer's own signed act carries this ATR's hash: a Hedera crypto transfer whose memo is the hash's LCP string reached consensus with SUCCESS, debiting the payer, the one account its rows debit, and paid the account it credits, recorded with the asset and amount it moved. The memo is in the public transaction record, readable by transaction id. It compares no amount, asset or time with the ATR's terms.

**`mpp/session/hedera/stock`**: Before this session, an account signed an agreement transaction carrying this ATR's hash on the session's Hedera network. The opening the credential names reached consensus: the account its ChannelOpened log names as payer deposited the deposit into the escrow's channel, whose payee the log names, after the block the agreement was recorded at. The opening does not carry the hash, and this does not show that the account that signed the agreement is the one that opened the channel unless the record compares the two. Vouchers sign the channel id and an amount, not the hash. This does not show that amount, deposit, payee or timing match the ATR's content.

**`x402/exact/hedera`**: The payer's own signed act carries this ATR's hash: a Hedera crypto transfer whose memo is the hash's LCP string reached consensus with SUCCESS, debiting the payer, the one account its rows debit, and paid the account it credits, recorded with the asset and amount it moved. The memo is in the public transaction record, readable by transaction id. It compares no amount, asset or time with the ATR's terms.

**`x402/exact/hedera/transfer-executor`**: Before this payment was taken, an account signed an agreement carrying this ATR's hash on \<network>, recorded in \<transaction>; this does not show that the account is the payer. The payment is an x402 transferExecutor payment on Hedera: the payer's executor contract moved the funds under an authorization the seller did not read, and the facilitator submitted the transaction. The hash reached the payer only in the challenge's extension, and nothing the payer signed carries it. The read of the named transaction's merged consensus record found that its one debited account is the payer recorded when the payment was presented, and that it credited the payee. It compares no amount, asset or time with the ATR's terms.

## Algorand

| Pairing | Coverage | Confirmed | Agreement payment first | Pays an agreement | TypeScript | Python |
| --- | --- | --- | --- | --- | --- | --- |
| `x402/exact/algorand` | full | yes | no | yes | `exactAvm` from `@integraledger/lcp/avm` | `X402_EXACT_ALGORAND` |

**`x402/exact/algorand`**: The payer's account authorized an Algorand asset transfer whose note is this ATR's hash in LCP string form, with a key's signature, a multisignature or a Falcon signature, by the account's own key or the key it is rekeyed to; a logic signature, or a transfer that names an asset sender, is no such act. The ledger verified that authorization when it confirmed the transaction, which is final on confirmation, and the note is on chain in it. Where the transfer moved an amount, zero included, the payer paid it to the account the transfer names (`arcv`). As an agreement, it shows that this account signed the transfer carrying the hash. It does not show that amount, asset or timing match the ATR's content.

## Aptos

| Pairing | Coverage | Confirmed | Agreement payment first | Pays an agreement | TypeScript | Python |
| --- | --- | --- | --- | --- | --- | --- |
| `x402/exact/aptos` | none | yes | yes, any network | no | `exactAptos` from `@integraledger/lcp/aptos` | `X402_EXACT_APTOS` |

**`x402/exact/aptos`**: Before this payment was taken, an account signed an agreement transaction carrying this ATR's hash on \<network>, recorded in \<transaction>; this shows neither that the account is the payer nor what the agreement moved. The ATR was assembled before the challenge went out, and the challenge advertised its hash and link. The payer's signed Aptos transaction does not carry the hash. The resource server tied the hash to this payment when it recorded the hash for this request, and the read identified the payment as the sender's committed transaction at its signed sequence number, signed by an account other than the option's payee and depositing to a store the payee owns. What it moved is recorded as observed: this does not show that amount, asset or timing match the ATR's content.

## Sui

| Pairing | Coverage | Confirmed | Agreement payment first | Pays an agreement | TypeScript | Python |
| --- | --- | --- | --- | --- | --- | --- |
| `x402/exact/sui` | full | yes | no | yes | `exactSui` from `@integraledger/lcp/sui` | `X402_EXACT_SUI` |

**`x402/exact/sui`**: The payer, the sender, signed a Sui transaction whose one unused Pure input is this ATR's hash, and the network executed it successfully in a checkpoint after the position the read was given; the hash is on chain in its input list, readable by its digest while a node retains it. The sender is not the option's payee. Where the transaction moved value it paid each account a positive balance change names; where it moved nothing it was signed, naming the recipient its signed transfer names. What it moved is recorded as observed: this does not show that amount, coin type or timing match the ATR's content.

## NEAR

| Pairing | Coverage | Confirmed | Agreement payment first | Pays an agreement | TypeScript | Python |
| --- | --- | --- | --- | --- | --- | --- |
| `mpp/charge/nearintents` | none | no | yes, any network | no | `chargeNearIntents` from `@integraledger/lcp/mpp` | `MPP_CHARGE_NEARINTENTS` |
| `x402/exact/near` | full | yes | no | yes | `exactNear` from `@integraledger/lcp/near` | `X402_EXACT_NEAR` |

**`mpp/charge/nearintents`**: Before this payment was reported, an agreement transaction carrying this ATR's hash was signed on \<network>, recorded in \<transaction>; this shows neither that its signer is the payer nor when the deposit was made. The seller's MPP challenge carried the hash in its externalId. The deposit carries no hash, and its payer signed nothing that does. The seller reported it paid.

**`x402/exact/near`**: Paid: the payer's account signed a NEP-366 delegate action whose one ft_transfer carries this ATR's hash in its memo, in LCP string form, so the payer's own signed act carries the hash. The runtime verified that signature and ran the delegate, and the transfer succeeded on the token contract the delegate names, reaching the account its receiver_id names, both as read. The signer is the delegate's sender, named apart from any other act's. This states nothing of the amount, nor that the token, the account reached or the time meet a term of the ATR.

## Starknet

| Pairing | Coverage | Confirmed | Agreement payment first | Pays an agreement | TypeScript | Python |
| --- | --- | --- | --- | --- | --- | --- |
| `x402/exact/starknet` | full | yes | no | yes | `exactStarknet` from `@integraledger/lcp/starknet` | `X402_EXACT_STARKNET` |

**`x402/exact/starknet`**: The payer's own signed SNIP-9 outside execution carries the low 250 bits of this ATR's hash as its nonce (on an agreement, of the agreement's value of it), which the payer's account verified when it executed it. It paid the account each `Transfer` from the payer, or a transfer call of zero, names the amount it states, zero included: on a payment, the option's `payTo` among them; where the read observed no transfer, the payer signed it. A holder of the ATR confirms the hash's low 250 bits from the nonce; the chain holds no more of it. This does not show that the amount, the asset or the timing match the ATR's content.

## Polkadot

| Pairing | Coverage | Confirmed | Agreement payment first | Pays an agreement | TypeScript | Python |
| --- | --- | --- | --- | --- | --- | --- |
| `x402/exact/polkadot/lcp-assets-remark` | full | yes | no | yes | `exactPolkadotRemark` from `@integraledger/lcp/polkadot` | `X402_EXACT_POLKADOT_LCP_ASSETS_REMARK` |

**`x402/exact/polkadot/lcp-assets-remark`**: The payer signed one Polkadot Asset Hub extrinsic whose bytes hold this ATR's hash in LCP string form as a remark, at the account nonce its reference holds, or an account acting for the payer through a `proxy.proxy` or `multisig.as_multi_threshold_1` wrapper signed one. The chain verified the signature and dispatched the extrinsic with a Remarked event for that remark, at the finality recorded. Where the record shows a transfer event from the payer, or the call is a transfer of zero that runs as the payer, it states that the extrinsic paid, with each recipient and what moved; where it shows neither, it states that the payer signed. The signer is named, with the wrapper as its authority where it acted for the payer. This does not show that amount, asset or timing match the ATR's content.

## TRON

| Pairing | Coverage | Confirmed | Agreement payment first | Pays an agreement | TypeScript | Python |
| --- | --- | --- | --- | --- | --- | --- |
| `x402/exact/tron/lcp-trc20-memo` | full | yes | no | yes | `exactTronMemo` from `@integraledger/lcp/tron` | `X402_EXACT_TRON_LCP_TRC20_MEMO` |

**`x402/exact/tron/lcp-trc20-memo`**: The payer, the transaction's owner, signed a Tron transaction whose memo is this ATR's hash in LCP string form, and whose one contract calls transfer on the token. The network verified the signature, which covers the memo through the transaction id, and the receipt's result is SUCCESS, at the finality recorded. Where the receipt holds Transfer logs from the owner, the transaction paid, with each recipient and what moved; where it holds no Transfer log and the signed call is a transfer of zero, it paid zero to that call's recipient; where it holds neither, the payer signed, and no account is named. The owner is named as the signer, and its Permission_id as the authority. This does not show that amount, token or timing match the ATR's content.

## TON

| Pairing | Coverage | Confirmed | Agreement payment first | Pays an agreement | TypeScript | Python |
| --- | --- | --- | --- | --- | --- | --- |
| `x402/exact/tvm` | full | yes | no | yes | `exactTvm` from `@integraledger/lcp/tvm` | `X402_EXACT_TVM` |

**`x402/exact/tvm`**: The payer's W5 wallet signed a request whose one Jetton transfer carries this ATR's hash in its forward payload, as a TEP-74 text comment in LCP string form, and ran it: the payer's own signed act carries the hash. The W5 wallet paid, through its Jetton wallet, the amount the `internal_transfer` names, zero included, to the Jetton wallet that took it, the recipient; where the read observed no transfer, the W5 wallet signed. The signer is the W5 wallet, named apart from the recipient. This does not show that the amount, the Jetton, the payee or the time match the ATR's content.

## Cardano

| Pairing | Coverage | Confirmed | Agreement payment first | Pays an agreement | TypeScript | Python |
| --- | --- | --- | --- | --- | --- | --- |
| `x402/exact/cardano` | full | yes | no | yes | `exactCardano` from `@integraledger/lcp/cardano` | `X402_EXACT_CARDANO` |
| `x402/exact/cardano/lock` | full | no | no | no | `exactCardanoLock` from `@integraledger/lcp/cardano` | `X402_EXACT_CARDANO_LOCK` |

**`x402/exact/cardano`**: The payer, the payment credential that holds the input the payment names, signed a Cardano transaction whose body commits through its auxiliary_data_hash to a CIP-20 message (label 674) carrying this ATR's hash, and the ledger included it as valid at the mark read. It paid: the read names each output it created, to which payment credential and in what asset and amount, as observed, and on a payment one output reached the payee's payment credential. A transaction with fewer confirmations than the ledger's security parameter (2160 on mainnet) can be rolled back. The read compares no amount, asset or time with the ATR's terms.

**`x402/exact/cardano/lock`**: The payer, the payment credential that holds the input the payment names, signed a Cardano transaction whose body commits through its auxiliary_data_hash to a CIP-20 message (label 674) carrying this ATR's hash, and the ledger included it as valid at the mark read. It deposited into a contract: the read names each output it created, as observed, and on a Masumi lock the beneficiary its escrow datum names. A deposit is a charge and never an agreement. The read compares no amount, asset or time with the ATR's terms.

## Casper

| Pairing | Coverage | Confirmed | Agreement payment first | Pays an agreement | TypeScript | Python |
| --- | --- | --- | --- | --- | --- | --- |
| `x402/exact/casper` | full | no | no | yes | `exactCasper` from `@integraledger/lcp/casper` | `X402_EXACT_CASPER` |

**`x402/exact/casper`**: The payer's own signed CEP-3009 authorization carries this ATR's hash as its nonce (on an agreement, the agreement's value of it), which the token contract verified with the payer's key when it executed the call. It paid the account its `to` names the amount its `value` states, zero included: on a payment, the option's `payTo`. This does not show that the amount, the asset or the timing match the ATR's content.

## Concordium

| Pairing | Coverage | Confirmed | Agreement payment first | Pays an agreement | TypeScript | Python |
| --- | --- | --- | --- | --- | --- | --- |
| `x402/exact/ccd` | full | no | no | no | `exactCcd` from `@integraledger/lcp/ccd` | `X402_EXACT_CCD` |

**`x402/exact/ccd`**: The payer signed a Concordium transaction one of whose transfers carries this ATR's hash, in LCP string form, as its memo. The chain accepted the transaction only with the sender's valid signature, and the memo is on chain in the finalized transfer event. Where the transfer moved an amount, zero included, the payer paid it to the account the transfer names. As an agreement, it shows that this account signed the transfer carrying the hash. It does not show that amount, token or timing match the ATR's content.

## Stacks

| Pairing | Coverage | Confirmed | Agreement payment first | Pays an agreement | TypeScript | Python |
| --- | --- | --- | --- | --- | --- | --- |
| `mpp/charge/usdc/stacks` | full | no | no | no | `chargeUsdcStacks` from `@integraledger/lcp/mpp` | `MPP_CHARGE_USDC_STACKS` |

**`mpp/charge/usdc/stacks`**: The payer signed a Stacks transaction whose origin is the payer and which carries this ATR's hash as the `(some H)` memo of a SIP-010 `transfer`, or as a token transfer's memo. The chain verified the origin's signature, the transaction executed with status success on the canonical chain, and the memo is in the mined transaction on chain. Where it made a transfer, one of zero included, it paid that transfer's recipient, named in the record; the origin, never a sponsor, is the signer. This does not show that the contract is a SIP-010 token, or that amount, asset or timing match the ATR's content.

## Lightning

| Pairing | Coverage | Confirmed | Agreement payment first | Pays an agreement | TypeScript | Python |
| --- | --- | --- | --- | --- | --- | --- |
| `mpp/charge/lightning` | none | no | yes, any network | no | `chargeLightning` from `@integraledger/lcp/lightning` | `MPP_CHARGE_LIGHTNING` |
| `mpp/session/lightning` | none | no | yes, any network | no | `sessionLightning` from `@integraledger/lcp/lightning` | `MPP_SESSION_LIGHTNING` |
| `x402/exact/lnbtc/payment-hash` | none | yes | yes, any network | no | `exactLnbtcPaymentHash` from `@integraledger/lcp/lightning` | `X402_EXACT_LNBTC_PAYMENT_HASH` |

**`mpp/charge/lightning`**: An account signed an agreement transaction carrying this ATR's hash on \<network>, recorded in \<transaction>, before this payment was taken or reported. This shows neither that the account is this payment's payer nor when this payment was taken, which nothing here reads. The seller's node's BOLT11 invoice's description hash is this ATR's hash, and the ATR commits its payment hash. The invoice is decoded strictly and its signer is recovered; no payee key is compared with that signer, and the payer signed nothing that carries the hash. The preimage, which every node on the payment's route learns, shows that the secret behind the hash left the seller's custody, never who paid, and to anyone but the seller's node not that the invoice was paid; no public ledger shows the payment. Settlement is the seller's report. This does not show that amount, payee or timing match the ATR's content.

**`mpp/session/lightning`**: An account signed an agreement transaction carrying this ATR's hash on \<network>, recorded in \<transaction>, before this payment was taken or reported. This shows neither that the account is this payment's payer nor when this payment was taken, which nothing here reads. The seller's node's BOLT11 invoice's description hash is this ATR's hash, and the ATR commits its payment hash. The invoice is decoded strictly and its signer is recovered; no payee key is compared with that signer, and the payer signed nothing that carries the hash. The preimage, which every node on the payment's route learns, shows that the secret behind the hash left the seller's custody, never who paid, and to anyone but the seller's node not that the invoice was paid; no public ledger shows the payment. Settlement is the seller's report. This does not show that amount, payee or timing match the ATR's content. The close is the seller's report.

**`x402/exact/lnbtc/payment-hash`**: An account signed an agreement transaction carrying this ATR's hash on \<network>, recorded in \<transaction>, before this payment was taken or reported. This shows neither that the account is this payment's payer nor when this payment was taken, which nothing here reads. The ATR commits the payment hash of the BOLT11 invoice paid, whose signer is held to the option's payTo; the payer signed nothing that carries the hash. The preimage, which every node on the payment's route learns, shows that the secret behind the hash left the seller's custody, never who paid, and to anyone but the seller's node not that the invoice was paid; no public ledger shows the payment. Settlement is the seller's report. This does not show that amount, payee or timing match the ATR's content.

## Cloudflare

| Pairing | Coverage | Confirmed | Agreement payment first | Pays an agreement | TypeScript | Python |
| --- | --- | --- | --- | --- | --- | --- |
| `x402/batch-settlement/cloudflare` | none | no | yes, any network | no | `batchCloudflare` from `@integraledger/lcp/x402-batch-settlement` | `X402_BATCH_SETTLEMENT_CLOUDFLARE` |

**`x402/batch-settlement/cloudflare`**: Before this payment was taken, an account signed an agreement transaction carrying this ATR's hash on \<network>, recorded in \<transaction>; this shows neither that the account is the payer nor what the agreement moved. The request whose payment echoed this ATR's hash in the legalContext entry of x402's extensions was signed with an HTTP message signature key registered with Cloudflare, which Cloudflare verifies, billing that key's registered identity off chain; no public ledger records the payment. This does not show that amount, asset or timing match the ATR's content.

## Card

| Pairing | Coverage | Confirmed | Agreement payment first | Pays an agreement | TypeScript | Python |
| --- | --- | --- | --- | --- | --- | --- |
| `card/mastercard-agent-pay` | none | no | yes, any network | no | `agentPay` from `@integraledger/lcp/card` | `CARD_MASTERCARD_AGENT_PAY` |
| `card/mastercard-vi/autonomous` | none | no | yes, any network | no | `viAutonomous` from `@integraledger/lcp/card` | `CARD_MASTERCARD_VI_AUTONOMOUS` |
| `card/mastercard-vi/immediate` | none | no | yes, any network | no | `viImmediate` from `@integraledger/lcp/card` | `CARD_MASTERCARD_VI_IMMEDIATE` |
| `card/seller-reference` | none | no | yes, any network | no | `sellerReference` from `@integraledger/lcp/card` | `CARD_SELLER_REFERENCE` |
| `card/visa-tap` | none | no | yes, any network | no | `visaTap` from `@integraledger/lcp/card` | `CARD_VISA_TAP` |
| `card/visa-vic` | none | no | yes, any network | no | `visaVic` from `@integraledger/lcp/card` | `CARD_VISA_VIC` |
| `mpp/charge/card` | none | no | yes, any network | no | `chargeCard` from `@integraledger/lcp/mpp` | `MPP_CHARGE_CARD` |

**`card/mastercard-agent-pay`**: An account signed an agreement transaction carrying this ATR's hash on \<network>, recorded in \<transaction>, before this payment was taken or reported. This shows neither that the account is this payment's payer nor when this payment was taken, which nothing here reads. Every Mastercard Agent Pay message signature in the agent's checkout request, tagged Agent-pay-auth or agent-pay-auth, covers this ATR's hash: its nonce, whose first 32 bytes are the hash, or the request's path, whose last segment is the hash. The seller checked where the hash rides and did not verify a signature here, and nothing compares the agent's key with the account that signed the agreement. The card authorization itself does not carry the hash. This does not show that amount, payee or timing match the ATR's content.

**`card/mastercard-vi/autonomous`**: An account signed an agreement transaction carrying this ATR's hash on \<network>, recorded in \<transaction>, before this payment was taken or reported. This shows neither that the account is this payment's payer nor when this payment was taken, which nothing here reads. An agent signed a Verifiable Intent L3b checkout mandate whose checkout_hash is the SHA-256 of a checkout_jwt carrying this ATR's hash, with the key the presented L2 mandate delegates to it. The seller verified both ES256 signatures and the sd_hash links, but not the L1 issuer's signature, and nothing compares the L2 or L3b signer with the account that signed the agreement. The L2 signature does not cover the hash, and the seller did not see the L3a payment mandate the network received, whose transaction_id Verifiable Intent requires to equal this checkout_hash. This does not show that amount, payee or timing match the ATR's content.

**`card/mastercard-vi/immediate`**: An account signed an agreement transaction carrying this ATR's hash on \<network>, recorded in \<transaction>, before this payment was taken or reported. This shows neither that the account is this payment's payer nor when this payment was taken, which nothing here reads. The Verifiable Intent L2 mandate presented lists a checkout mandate whose checkout_hash is the SHA-256 of a checkout_jwt carrying this ATR's hash, and the payment mandate's transaction_id, where disclosed, equals it. The seller checked those values and did not verify the L2 mandate's signature, which Verifiable Intent has the payment network validate before authorization, and nothing compares the L2 mandate's signer with the account that signed the agreement. The card authorization itself does not carry the hash. This does not show that amount, payee or timing match the ATR's content.

**`card/seller-reference`**: An account signed an agreement transaction carrying this ATR's hash on \<network>, recorded in \<transaction>, before this payment was taken or reported. This shows neither that the account is this payment's payer nor when this payment was taken, which nothing here reads. This ATR's hash and link are for the seller to show the buyer before payment and to put in its processor's metadata under legal_context, beside the seller's own reference for the charge. Nothing the payer signed for this payment carries the hash, and the payment is known from the seller's report alone, which names it by that reference. This does not show that the payer's approval carried the hash.

**`card/visa-tap`**: An account signed an agreement transaction carrying this ATR's hash on \<network>, recorded in \<transaction>, before this payment was taken or reported. This shows neither that the account is this payment's payer nor when this payment was taken, which nothing here reads. Every TAP agent-payer-auth message signature in the agent's checkout request covers this ATR's hash: its nonce, whose first 32 bytes are the hash, or the request's path, whose last segment is the hash. The seller checked where the hash rides and did not verify a signature here, which belongs to its TAP recognition step, and nothing compares the agent's key with the account that signed the agreement. The card authorization itself does not carry the hash. This does not show that amount, payee or timing match the ATR's content.

**`card/visa-vic`**: An account signed an agreement transaction carrying this ATR's hash on \<network>, recorded in \<transaction>, before this payment was taken or reported. This shows neither that the account is this payment's payer nor when this payment was taken, which nothing here reads. The agent's Visa Intelligent Commerce credential request carried this ATR's hash as its transactionReferenceId, which the seller read from the credential payload Visa signs for the sale. Verifying that payload is the seller's and was not done here, and nothing compares the agent or the cardholder with the account that signed the agreement. The card authorization itself does not carry the hash. This does not show that amount, payee or timing match the ATR's content.

**`mpp/charge/card`**: An account signed an agreement transaction carrying this ATR's hash on \<network>, recorded in \<transaction>, before this payment was taken or reported. This shows neither that the account is this payment's payer nor when this payment was taken, which nothing here reads. The seller's MPP challenge carried this ATR's hash in its id and its opaque reference, bound to the challenge by the seller's own server, and the credential presented echoed that challenge. The seller also placed the hash in the request's externalId. Nothing the payer or its card signed carries the hash, and the payment is known from the seller's report alone. This does not show that the payer's approval carried the hash.

## Stripe

| Pairing | Coverage | Confirmed | Agreement payment first | Pays an agreement | TypeScript | Python |
| --- | --- | --- | --- | --- | --- | --- |
| `mpp/charge/stripe` | none | no | yes, any network | no | `chargeStripe` from `@integraledger/lcp/mpp` | `MPP_CHARGE_STRIPE` |
| `mpp/subscription/stripe` | none | no | yes, any network | no | `subscriptionStripe` from `@integraledger/lcp/mpp` | `MPP_SUBSCRIPTION_STRIPE` |

**`mpp/charge/stripe`**: An account signed an agreement transaction carrying this ATR's hash on \<network>, recorded in \<transaction>, before this payment was taken or reported. This shows neither that the account is this payment's payer nor when this payment was taken, which nothing here reads. The seller's MPP challenge carried this ATR's hash in its id and its opaque reference, bound to the challenge by the seller's own server, and the credential presented echoed that challenge. The seller also placed the hash in the PaymentIntent's metadata under legal_context. Nothing the payer or its Stripe token signed carries the hash, and the payment is known from the seller's report alone. This does not show that the payer's approval carried the hash.

**`mpp/subscription/stripe`**: An account signed an agreement transaction carrying this ATR's hash on \<network>, recorded in \<transaction>, before this payment was taken or reported. This shows neither that the account is this payment's payer nor when this payment was taken, which nothing here reads. The seller's MPP challenge carried this ATR's hash in its id and its opaque reference, bound to the challenge by the seller's own server, and the credential presented echoed that challenge. The seller also placed the hash in the metadata under legal_context of the payment that activates the subscription. Nothing the payer or its Stripe token signed carries the hash, and the activation is known from the seller's report alone. This does not show that the payer's approval carried the hash.

## Mandate

| Pairing | Coverage | Confirmed | Agreement payment first | Pays an agreement | TypeScript | Python |
| --- | --- | --- | --- | --- | --- | --- |
| `ap2/checkout-mandate` | none | no | yes, any network | no | `checkoutMandate` from `@integraledger/lcp/ap2` | `AP2_CHECKOUT_MANDATE` |
| `ap2/checkout-mandate/x402` | none | no | yes, any network | no | `checkoutMandateX402` from `@integraledger/lcp/ap2` | `AP2_CHECKOUT_MANDATE_X402` |
| `ucp/booking/ap2-mandate` | none | no | yes, any network | no | `bookingAp2Mandate` from `@integraledger/lcp/ucp` | `UCP_BOOKING_AP2_MANDATE` |
| `ucp/checkout/ap2-mandate` | none | no | yes, any network | no | `ap2Mandate` from `@integraledger/lcp/ucp` | `UCP_CHECKOUT_AP2_MANDATE` |

**`ap2/checkout-mandate`**: An account signed an agreement transaction carrying this ATR's hash on \<network>, recorded in \<transaction>, before this payment was taken or reported. This shows neither that the account is this payment's payer nor when this payment was taken, which nothing here reads. The closed AP2 Checkout Mandate presented carries checkout_hash, the SHA-256 of the checkout JWT presented beside it, and that JWT's payload carries this ATR's hash as its legalContext member. AP2 has the mandate signed by the user's trusted surface, or by the agent under the user's open mandate presented before it in a chain. That signature, the open mandate's signature, its delegation to the agent's key (cnf) and the chain's link were not verified here, and nothing compares the mandate's signer with the account that signed the agreement: AP2 has the Credential Provider verify the Payment Mandate, whose transaction_id is the same hash, before a payment credential issues. The payment, whether the merchant initiated it or the payer's side sent it, is known from the seller's report alone. This does not show that amount, payee or timing match the ATR's content.

**`ap2/checkout-mandate/x402`**: An account signed an agreement transaction carrying this ATR's hash on \<network>, recorded in \<transaction>, before this payment was taken. This does not show that the account is this payment's payer. The payment paid \<amount> of the token \<asset> to \<recipient> in \<payment transaction> on \<payment network>: an EIP-3009 transfer authorization whose nonce is keccak-256 of the payment mandate chain it was presented with, as AP2's payment processor requires, and whose chain's closed Payment Mandate names, as its transaction_id, the checkout_hash of the closed AP2 Checkout Mandate presented. That checkout_hash is the SHA-256 of the checkout JWT presented beside it, and that JWT's payload carries this ATR's hash as its legalContext member; the payment itself carries no hash of this ATR. No mandate signature was verified here: AP2 has the Credential Provider verify the mandates. This does not show that amount, payee or timing match the ATR's content.

**`ucp/booking/ap2-mandate`**: An account signed an agreement transaction carrying this ATR's hash on \<network>, recorded in \<transaction>, before this payment was taken or reported. This shows neither that the account is this payment's payer nor when this payment was taken, which nothing here reads. The booking carried this ATR's hash and link as its legal_context link. The checkout mandate presented under UCP's AP2 Mandates extension carries checkout_hash, the SHA-256 of the booking JWT presented beside it, and the hash was read from that JWT's booking. The mandate's signature, and, where an open mandate precedes it in a chain, that mandate's signature, its delegation (cnf) and the chain's link, were not verified here, and nothing compares the mandate's signer with the account that signed the agreement; the PSP verifies the payment mandate over the same booking hash. The payment is known from the seller's report alone. This does not show that amount, payee or timing match the ATR's content.

**`ucp/checkout/ap2-mandate`**: An account signed an agreement transaction carrying this ATR's hash on \<network>, recorded in \<transaction>, before this payment was taken or reported. This shows neither that the account is this payment's payer nor when this payment was taken, which nothing here reads. The checkout carried this ATR's hash and link as its legal_context link. The checkout mandate presented under UCP's AP2 Mandates extension carries checkout_hash, the SHA-256 of the checkout JWT presented beside it, and the hash was read from that JWT's checkout. The mandate's signature, and, where an open mandate precedes it in a chain, that mandate's signature, its delegation (cnf) and the chain's link, were not verified here, and nothing compares the mandate's signer with the account that signed the agreement; the PSP verifies the payment mandate over the same checkout hash. The payment is known from the seller's report alone. This does not show that amount, payee or timing match the ATR's content.

## Checkout

| Pairing | Coverage | Confirmed | Agreement payment first | Pays an agreement | TypeScript | Python |
| --- | --- | --- | --- | --- | --- | --- |
| `ack/payment-request` | none | no | yes, any network | no | `paymentRequest` from `@integraledger/lcp/ack` | `ACK_PAYMENT_REQUEST` |
| `acp/checkout/delegated` | none | no | yes, any network | no | `delegated` from `@integraledger/lcp/acp` | `ACP_CHECKOUT_DELEGATED` |
| `acp/checkout/undelegated` | none | no | yes, any network | no | `undelegated` from `@integraledger/lcp/acp` | `ACP_CHECKOUT_UNDELEGATED` |
| `ucp/booking/unsigned` | none | no | yes, any network | no | `bookingUnsigned` from `@integraledger/lcp/ucp` | `UCP_BOOKING_UNSIGNED` |
| `ucp/checkout/agent-signed` | none | no | yes, any network | no | `agentSigned` from `@integraledger/lcp/ucp` | `UCP_CHECKOUT_AGENT_SIGNED` |
| `ucp/checkout/unsigned` | none | no | yes, any network | no | `unsigned` from `@integraledger/lcp/ucp` | `UCP_CHECKOUT_UNSIGNED` |

**`ack/payment-request`**: An account signed an agreement transaction carrying this ATR's hash on \<network>, recorded in \<transaction>, before this payment was taken or reported. This shows neither that the account is this payment's payer nor when this payment was taken, which nothing here reads. This ATR's hash is the id of the seller's ACK Payment Request token, with the link beside it; a receipt for that request embeds the token. The token's signature is not verified here. ACK defines no payer signature, so nothing the payer signed carries the hash, and the payment, which the payer's side sends before it presents the receipt, is known from the seller's report alone. This does not show that the payer's approval carried the hash.

**`acp/checkout/delegated`**: An account signed an agreement transaction carrying this ATR's hash on \<network>, recorded in \<transaction>, before this payment was taken or reported. This shows neither that the account is this payment's payer nor when this payment was taken, which nothing here reads. The checkout session this payment completed has this ATR's hash as its id, and its responses carried the ATR's link in metadata. The payment handler required delegate_payment, so ACP has the agent obtain a vault token whose allowance names this session as checkout_session_id, in a request the agent signs (a MUST in one section of ACP and RECOMMENDED in another) and the PSP SHOULD verify. No signature was verified here, nothing compares the agent's signer with the account that signed the agreement, and ACP does not require the PSP to hold the token to that session. The payment is known from the seller's report alone. This does not show that amount, payee or timing match the ATR's content.

**`acp/checkout/undelegated`**: An account signed an agreement transaction carrying this ATR's hash on \<network>, recorded in \<transaction>, before this payment was taken or reported. This shows neither that the account is this payment's payer nor when this payment was taken, which nothing here reads. The checkout session this payment completed has this ATR's hash as its id, and its responses carried the ATR's link in metadata. The payment handler did not require delegate_payment, so nothing the payer signed for the payment names the hash. The payment is known from the seller's report alone, which names it by the seller's own reference for the charge.

**`ucp/booking/unsigned`**: An account signed an agreement transaction carrying this ATR's hash on \<network>, recorded in \<transaction>, before this payment was taken or reported. This shows neither that the account is this payment's payer nor when this payment was taken, which nothing here reads. The booking response carried this ATR's hash and link as its legal_context link. UCP without the AP2 Mandates extension defines no buyer signature, so the payer's approval did not sign the hash. The payment is known from the seller's report alone.

**`ucp/checkout/agent-signed`**: An account signed an agreement transaction carrying this ATR's hash on \<network>, recorded in \<transaction>, before this payment was taken or reported. This shows neither that the account is this payment's payer nor when this payment was taken, which nothing here reads. The checkout response carried this ATR's hash and link as its legal_context link, and the platform's request that completed the checkout carried the hash in its legal_context member, with a Content-Digest that is the SHA-256 of that request's body. The platform's RFC 9421 signature over the request, which UCP has the business verify with the key in the platform's profile, was not verified here, and nothing ties that key to the account that signed the agreement. The seller reported the payment. This does not show that amount, payee or timing match the ATR's content.

**`ucp/checkout/unsigned`**: An account signed an agreement transaction carrying this ATR's hash on \<network>, recorded in \<transaction>, before this payment was taken or reported. This shows neither that the account is this payment's payer nor when this payment was taken, which nothing here reads. The checkout response carried this ATR's hash and link as its legal_context link. UCP without the AP2 Mandates extension defines no buyer signature, so the payer's approval did not sign the hash. The payment is known from the seller's report alone, which names it by the seller's own reference for the charge.
