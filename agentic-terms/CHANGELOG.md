# Changelog

Every notable change to `@integraledger/terms`, and to `@integraledger/terms-mcp` and `integraledger-terms`, which are
released with it under the same version. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The packages are at 0.x: a minor release may change the public API. A change a caller must make is marked
**Breaking**; [Upgrading](https://github.com/IntegraLedger/integra-agentic-terms/blob/main/docs/upgrading.md) shows each
call before and after.

## [Unreleased]

### Changed

- The peer dependency on `@integraledger/lcp` is `~0.6.3` (was `~0.6.2`): the gate shows the `approve` call 0.6.3's
  v1 Tempo session build hands the wallet before the `open`, and reads `mpp/subscription/solana` in the form 0.6.3
  reads it.

### Fixed

- The gate shows and signs an `x402/batch-settlement/solana` opening: the profile `buyer-gate.md`, rule 13, fills its
  row, the `batch` of the `open` message and the first voucher, which must be for the `open`'s authorized signer, over
  the channel the `open` opens, with no expiry. The summary holds the voucher's amount, split by the `open`'s
  distribution, the deposit and the mint. Such an opening was declined `summary-missing`.
- The summary of a payment channel's `open` on Solana (`x402/upto/solana`, `mpp/session/solana/memo` and the
  `x402/batch-settlement/solana` opening) shows the channel's payee with the rest of the amount where the
  distribution's basis points sum to less than 10,000, as the payment-channels program pays it; a share of 0 points, or
  points that sum past 10,000, gives no summary. An opening with splits, such as an MPP session challenge's `splits`,
  was declined `summary-missing`.
- The gate shows and signs a Masumi lock of `x402/exact/cardano/lock`: its payee is the seller the option's
  `extra.terms.sellerAddress` names, as lcp's reference names it, with the amount, and its `grant` is `{escrow}`,
  `payTo`, the escrow that holds the deposit. Such a lock was declined `summary-missing`.
- The profile `buyer-gate.md`, rule 8, states how a subscription's expiry is held: on `mpp/subscription/tempo` the
  window is the key authorization's `expiry`, the challenge's `subscriptionExpires`, less the gate's clock, and a
  subscription longer than 600 seconds is paid once `ceilings` raises the pairing's ceiling to that window.
- A Masumi lock's summary shows, in its `grant`, every party that can move the locked funds, and when, as the
  `vested_pay` escrow gates each: the seller after `unlockTime`, the buyer's refund after `submitResultTime`, and the
  deployment's admins, each distinct key hash with its weight and the weight required, after
  `externalDisputeUnlockTime`, the canonical deployment's where the option names none.
- The summary of a payment channel's `open` on Solana (`x402/upto/solana`, `mpp/session/solana/memo` and the
  `x402/batch-settlement/solana` opening) holds `closableBy`: the `open`'s payee and its payer, as the payment-channels
  program lets each close.
- `mpp/session/tempo`'s v1 opening shows the currency's `approve(escrow, deposit)` that precedes the escrow's `open`
  in the `tempo-call` request, as `grant.approve`, `{token, spender, amount}`, and has no summary where that `approve`
  names another token or spender than the `open`'s, or more than its deposit. A v1 escrow takes the deposit with
  `transferFrom`, so an `open` sent alone reverts with `InsufficientAllowance()`.
- `mpp/subscription/solana` follows the protocol package's reading of `@solana/pay-kit` 0.13.1's challenge: the guide
  names `planAddress` and `subscriptionProgram`.

## [0.5.2] - 2026-11-20

### Added

- `transact` pays a card or checkout sale whose agreement the first response offers as an x402 or MPP option (lcp
  profile `legal-context-return.md`, rule 6): given the charge's pairing, of `card`, `acp`, `ap2`, `ucp` or `ack`, with
  that response, it pays the agreement for a served option of the ATR's binding slot that the pairing pays for the
  account and returns `ToReturn` with `charge` such as `card/0`; the second call, with the seller's document served
  after the return, pays the charge. Such a response was declined `offer-unreadable`. `vectors/buyer-gate.json` holds
  `serves-card-charge` and `serves-card-unserved`, which both languages run.

### Changed

- The peer dependency on `@integraledger/lcp` is `~0.6.2` (was `~0.6.0`): the gate reads an agreement option's served
  names with 0.6.2's `servesOf`, which reads `<slot>/<i>` for every ATR binding slot that holds charge options:
  `ack/<i>`, `acp/<i>`, `ap2/<i>`, `card/<i>` and `ucp/<i>` beside `x402/<i>` and `mpp/<i>`.
- On the return after an agreement, `transact` resolves each agreement option's served names against the ATR's bytes
  once it has fetched and parsed them (lcp profile `legal-context-return.md`, rule 6): an option naming a slot that is
  not the ATR's binding slot, or an index not below the number of charge options that slot holds, is declined
  `offer-unreadable` with `return/serves-malformed` before any charge is chosen. `vectors/buyer-gate.json` holds a card
  sale's pair, `serves-card` and `serves-not-in-atr`, which both languages run.

## [0.5.1] - 2026-11-18

### Added

- `ceilings` in `agree`'s options (`AgreeOptions`), which raises the agreement payment's pairing's ceiling as
  `transact`'s does.
- `act` in `confirm`'s and `finish`'s options (`ConfirmOptions`, `FinishOptions`): `"payment"`, the default, or
  `"agreement"`, which builds and completes the agreement payment as `agree` does, for a caller that pays the agreement
  by hand. On `x402/exact/eip155/eip3009`, `x402/exact/eip155/permit2`, `x402/exact/casper` and `x402/exact/starknet`
  the agreement payment carries the agreement's own value of H, which a payment built as `"payment"` does not. A pairing
  whose payment cannot be an agreement is declined `no-payable-option`.
- `unpaid` in `AgreementReceipt`: `true` where the agreement URL answered the first, unpaid request with the receipt,
  so that the gate made no agreement payment and read none (the profile's new rule 18). `agree` returns such a receipt
  as `receipt`, and `transact` as `agreement`; it no longer reads as an agreement the gate saw recorded.

### Fixed

- The gate holds the option chosen to the ATR's binding slot on every protocol the profile's rule 6 names, as it did on
  x402 and MPP alone: the `options` of `acp`, `ap2`, `card` and `ucp` and the `paymentOptions` of `ack`. An option the
  slot does not list is declined `option-not-in-atr` before anything is signed. On `card`, whose documents do not show
  the seller's checkout id, a listed option of the pairing's `scheme` holds it. `vectors/buyer-gate.json` holds a
  declining and an accepted case for each of the five.
- `agree` holds the agreement payment to its summary and its own pairing's ceiling before it is signed, as `transact`
  does and the profile's rule 12 states: a request it has no summary for is declined `summary-missing`, one payable
  past the ceiling `past-ceiling` or `no-end`, and a wallet that picks its expiry (Aptos, Cardano, Sui, Polkadot) is
  handed the latest deadline it may sign and held to it. An agreement payment payable longer than 600 seconds is now
  paid only once `ceilings` raises its pairing. `agree` still calls no approver.

### Documentation

- The profile's rule 13 and the pages state why `within` holds a voucher to no summary or ceiling of its own: a voucher
  signs no deadline and pays only from the deposit of its opening, which the gate holds to its summary and ceiling
  before it is signed, and the hold keeps no copy of the opening's request.

## 0.5.0 - 2026-11-18

The gate now checks what the buyer signs before it signs, and asks an approver first. The checks, their order and the
decline each answers are fixed, for both languages, by the profile `profiles/buyer-gate.md`, and its vectors by
`vectors/buyer-gate.json`; both ship in the package.

### Added

- The checks before a signing, each with its decline code: the ATR's bytes parse as one JSON text both languages read
  alike (`atr-malformed`); on x402 and MPP, the option chosen is one the ATR's binding slot lists
  (`option-not-in-atr`), and on x402 the buyer's request is the one its request commitment names
  (`request-mismatch`); the request handed to the signer has a summary (`summary-missing`); the signed payment stays
  payable no longer than its pairing's ceiling (`past-ceiling`, `no-end`); a rail's served floor is given
  (`floor-missing`); and, in `transact`, the approver approves the signing (`not-approved`).
- The approver: `transact` asks the caller's `approver` about each signing, the agreement payment's and each later
  step's among them, with `ToSign`: the act, the pairing, the request and its `Summary` of every authority the signature
  grants (`Payee`, `Validity`, `SigningStep`).
- `resourceRequest`, the request the seller's offer answered, in `transact`'s and `confirm`'s options
  (`ResourceRequest`, the protocol package's `HttpRequest` or `ToolCall`).
- `ceilings` in the options of `transact`, `confirm` and `finish` (`Ceilings`): a pairing's ceiling is 600 seconds
  unless raised, or lifted with `"no-end"`.
- `FLOOR_INPUTS`: the floor inputs of `x402/exact/eip155/gateway-batched` and `mpp/charge/usdc/gateway`.
- The latest deadline handed to a wallet that picks its own expiry (`x402/exact/aptos`, `x402/exact/cardano`,
  `x402/exact/cardano/lock`, `x402/exact/sui`, `x402/exact/polkadot/lcp-assets-remark`), kept as `Chosen.deadline`, and
  the deadline the wallet signed read back before the payment is returned.
- The return after an agreement (the protocol package's profile `legal-context-return.md`): `transact` takes
  `legalContext` and returns `ToReturn` where the seller's first response offers the agreement alone.
- `AgreementChallenges`: where the agreement URL offers only MPP agreement challenges, `transact` and `agree` return
  them, signing nothing, for the caller's own MPP client.
- `chosen` in the options of `transact` and `agree`: `transact` builds the payment `confirm` chose, and `agree` pays only
  an agreement option the charge's pairing admits.
- `check`'s `act`, `"payment"` or `"agreement"`, so a kept agreement payment is confirmed as one.
- `viJson`, the JSON text a Mastercard Verifiable Intent signer signs, and its vectors, `vectors/vi-signer.json`.
- 19 pairings: `ap2/checkout-mandate/x402`, `card/mastercard-agent-pay`, `card/visa-vic`, `mpp/charge/lcp/hedera`,
  `mpp/charge/solana/unsponsored`, `mpp/charge/tempo/split-memo`, `mpp/charge/tempo/split-memo/push`,
  `mpp/session/hedera/stock`, `mpp/session/solana/memo`, `mpp/session/solana/stock`, `mpp/session/xrpl/stock`,
  `mpp/subscription/solana`, `spend-permissions/eip155`, `ucp/checkout/agent-signed`, `x402/exact/cardano/lock`,
  `x402/exact/eip155/gateway-batched`, `x402/exact/lnbtc/payment-hash`, `x402/exact/stellar/precondition` and
  `x402/upto/xrpl`. 77 in all.
- `@integraledger/terms-mcp`: `resourceRequest` on `atr_confirm` and `atr_transact`; the `summary` beside each request
  `atr_confirm` and `atr_finish` return; `legalContext` on `atr_transact`, and `ToReturn` and `agreementChallenges` in
  its results; `act` on `atr_check`; `ceilings` and `floors` options of `createBuyerServer`.
- `integraledger-terms`: the same checks, arguments and results, with Python names (`approver=`, `resource_request=`,
  `ceilings=`, `legal_context=`, `chosen=`, `act=`), `FLOOR_INPUTS` and `vi_json`.

### Changed

- **Breaking.** `transact`'s options are required and must hold `approver` and `resourceRequest`. A call without them is
  declined `no-payable-option` with `<namespace>/input-malformed` before anything is fetched. In Python, `approver=` and
  `resource_request=` are required keywords.
- **Breaking.** `confirm`'s fifth argument is `{ resourceRequest, inputs?, ceilings? }`, `inputs` moving into it. In
  Python, `confirm(…, *, resource_request, inputs=None, ceilings=None)`: `inputs` is keyword-only.
- **Breaking.** Every signed payment through `transact`, `confirm` and `finish` is held to its pairing's ceiling, 600
  seconds unless `ceilings` raises it, and a form that signs no end is declined `no-end`. On the XRP Ledger, Cardano and
  Sui the caller gives `ledgerIndex`, `currentSlot` and `currentEpoch` in `inputs`.
- **Breaking.** `transact` may also return `AgreementChallenges` and `ToReturn`, and `agree` `AgreementChallenges`.
- **Breaking.** `DeclineCode` holds eight more codes: `not-approved`, `atr-malformed`, `option-not-in-atr`,
  `request-mismatch`, `summary-missing`, `past-ceiling`, `no-end` and `floor-missing`.
- **Breaking.** The agreement payment is built and checked as the act `agreement`: on a pairing whose agreement has its
  own single-use value, it carries `agreementValue(H)` where 0.4.x carried H.
- **Breaking.** `@integraledger/terms-mcp`'s `atr_transact` signs nothing on its first call: it returns `approve`,
  `{ agreement?, signings }`, and signs only when called again with that value as `approved`, unchanged.
- `finish` takes `{ ceilings? }`, and returns a later step as `{ next, summary, h }`, held to its summary and its
  ceiling; in Python, `Next(next, summary, h)`.
- `Chosen` holds `deadline` where a wallet picks its expiry (in Python, also `act`).
- The agreement option paid follows the charge's `agreementOn`: any network, or the charge's own.
- The peer dependency on `@integraledger/lcp` is `~0.6.0` (0.4.x: `~0.5.1`), and Node.js `>=24.22.1` (0.4.x: `>=24`).

### Removed

- **Breaking.** The nine pairings the protocol package retired, with their bindings and Python constants:
  `mpp/charge/hedera`, `mpp/charge/stellar`, `mpp/charge/tempo/memo`, `mpp/charge/tempo/push`, `mpp/session/hedera`,
  `mpp/session/solana`, `x402/exact/lnbtc`, `x402/exact/lnbtc/invoice-named` and `x402/exact/stellar`.

Earlier releases are recorded in the repository's history.
