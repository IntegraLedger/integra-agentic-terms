# Changelog

Every notable change to `integraledger-terms`, which is released with `@integraledger/terms` under the same version. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The package is at 0.x: a minor release may
change the public API, so pin the exact version. A change a caller must make is marked **Breaking**;
[Upgrading](https://github.com/IntegraLedger/integra-agentic-terms/blob/main/docs/upgrading.md) shows each call before
and after.

## [Unreleased]

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

## [0.5.2] - 2026-11-20

### Added

- `transact` pays a card or checkout sale whose agreement the first response offers as an x402 or MPP option (lcp
  profile `legal-context-return.md`, rule 6): given the charge's pairing, of `card`, `acp`, `ap2`, `ucp` or `ack`, with
  that response, it pays the agreement for a served option of the ATR's binding slot that the pairing pays for the
  account and returns `ToReturn` with `charge` such as `card/0`; the second call, with the seller's document served
  after the return, pays the charge. Such a response was declined `offer-unreadable`. The shared
  `vectors/buyer-gate.json` holds `serves-card-charge` and `serves-card-unserved`.

### Fixed

- The gate reads an agreement option's served names as `@integraledger/lcp` 0.6.2's `servesOf` does (lcp profile
  `legal-context-return.md`, rule 6): `<slot>/<i>` for every ATR binding slot that holds charge options, `ack/<i>`,
  `acp/<i>`, `ap2/<i>`, `card/<i>` and `ucp/<i>` beside `x402/<i>` and `mpp/<i>`, 1 to 32 distinct names with an index
  from 0 to 31. It read `x402/<i>` and `mpp/<i>` alone, and declined a card or checkout sale's agreement option
  `offer-unreadable`.
- On the return after an agreement, `transact` resolves each served name against the ATR's bytes once it has fetched
  and parsed them: an option naming a slot that is not the ATR's binding slot, or an index not below the number of
  charge options that slot holds, is declined `offer-unreadable` with `return/serves-malformed` before any charge is
  chosen. The shared `vectors/buyer-gate.json` holds a card sale's pair, `serves-card` and `serves-not-in-atr`.

## [0.5.1] - 2026-11-18

### Added

- `ceilings=` in `agree`, which raises the agreement payment's pairing's ceiling as `transact`'s does.
- `act=` in `confirm` and `finish`: `"payment"`, the default, or `"agreement"`, which builds and completes the agreement
  payment as `agree` does, for a caller that pays the agreement by hand; `Confirmed.chosen.act` is then `"agreement"`.
  On `x402/exact/eip155/eip3009`, `x402/exact/eip155/permit2`, `x402/exact/casper` and `x402/exact/starknet` the
  agreement payment carries the agreement's own value of H, which a payment built as `"payment"` does not. A pairing
  whose payment cannot be an agreement is declined `no-payable-option`, and the agreement option and request are not
  held to the ATR's binding slot, which lists the charge's.
- `unpaid` in `AgreementReceipt`: `True` where the agreement URL answered the first, unpaid request with the receipt,
  so that the gate made no agreement payment and read none (the profile's new rule 18), and `False`, the default, where
  it answered the paid request. `agree` returns such a receipt in `Agreed`, and `transact` as `agreement`; it no longer
  reads as an agreement the gate saw recorded.

### Fixed

- The gate holds the option chosen to the ATR's binding slot on every protocol the profile's rule 6 names, as it did on
  x402 and MPP alone: the `options` of `acp`, `ap2`, `card` and `ucp` and the `paymentOptions` of `ack`. An option the
  slot does not list is declined `option-not-in-atr` before anything is signed. On `card`, whose documents do not show
  the seller's checkout id, a listed option of the pairing's `scheme` holds it. The shared `vectors/buyer-gate.json`
  holds a declining and an accepted case for each of the five, which the Python tests run.
- `agree` holds the agreement payment to its summary and its own pairing's ceiling before it is signed, as `transact`
  does and the profile's rule 12 states: a request it has no summary for is declined `summary-missing`, one payable
  past the ceiling `past-ceiling` or `no-end`, and a wallet that picks its expiry (Aptos, Cardano, Sui, Polkadot) is
  handed the latest deadline it may sign and held to it. An agreement payment payable longer than 600 seconds is now
  paid only once `ceilings=` raises its pairing. `agree` still calls no approver.

### Documentation

- The profile's rule 13 and the pages state why `within` holds a voucher to no summary or ceiling of its own: a voucher
  signs no deadline and pays only from the deposit of its opening, which the gate holds to its summary and ceiling
  before it is signed, and the hold keeps no copy of the opening's request.

## 0.5.0 - 2026-11-18

Brings the Python gate to the calls of `@integraledger/terms` 0.5.0, and builds and reads every pairing as
`@integraledger/lcp` 0.6.0 does. Every 0.4.x caller changes something: the entries marked **Breaking** say what.

### Added

- `transact` takes `approver=`, called once for each signing with a `ToSign` (its act, pairing, request, `Summary` and
  `SigningStep`) before the signer is called for it, and signs only on `True`. It also takes `ceilings=`,
  `legal_context=` and `chosen=`.
- `confirm` returns the request with its `summary` (`Confirmed.summary`), every authority signing it grants (terms'
  profile `buyer-gate.md`, rule 13), and takes `ceilings=`. `finish` takes `ceilings=`, and returns a later step with
  its summary (`Next.summary`).
- `check` takes `act`: `"agreement"` for an agreement payment, `"payment"` by default.
- `agree` takes `chosen=`, and then pays only an agreement option the charge's pairing can follow, by its `agreementOn`
  in the protocol package's registry.
- Where the seller's first response offers only the agreement, `transact` pays the agreement and returns `ToReturn`,
  signing no charge (the protocol package's profile `legal-context-return.md`). Where the agreement URL offers only MPP
  agreement challenges, `transact` and `agree` return `AgreementChallenges`, signing nothing.
- Exports: `ToReturn`, `AgreementChallenges`, `ToSign`, `SigningStep`, `Summary`, `Payee`, `Validity`, `Approver`,
  `Ceilings`, `ResourceRequest`, `HttpRequest`, `ToolCall`, `FLOOR_INPUTS` and `vi_json`. `Chosen` gains `act` and
  `deadline`.
- `DeclineCode` gains `not-approved`, `atr-malformed`, `option-not-in-atr`, `request-mismatch`, `summary-missing`,
  `past-ceiling`, `no-end` and `floor-missing`.
- Bindings: `AP2_CHECKOUT_MANDATE_X402`, `CARD_MASTERCARD_AGENT_PAY`, `CARD_VISA_VIC`, `MPP_CHARGE_LCP_HEDERA`,
  `MPP_CHARGE_SOLANA_UNSPONSORED`, `MPP_CHARGE_TEMPO_SPLIT_MEMO`, `MPP_CHARGE_TEMPO_SPLIT_MEMO_PUSH`,
  `MPP_SESSION_HEDERA_STOCK`, `MPP_SESSION_SOLANA_MEMO`, `MPP_SESSION_SOLANA_STOCK`, `MPP_SESSION_XRPL_STOCK`,
  `MPP_SUBSCRIPTION_SOLANA`, `SPEND_PERMISSIONS_EIP155`, `UCP_CHECKOUT_AGENT_SIGNED`, `X402_EXACT_CARDANO_LOCK`,
  `X402_EXACT_EIP155_GATEWAY_BATCHED`, `X402_EXACT_LNBTC_PAYMENT_HASH`, `X402_EXACT_STELLAR_PRECONDITION` and
  `X402_UPTO_XRPL`.

### Changed

- **Breaking.** `confirm(doc, binding, account, fetch, *, resource_request, inputs=None, ceilings=None)` (was
  `confirm(doc, binding, account, fetch, inputs=None)`): `resource_request`, the request the seller's offer answered,
  is required, and `inputs` is a keyword. A 0.4.x call raises `TypeError`.
- **Breaking.** `transact` requires `approver=` and `resource_request=`; a 0.4.x call raises `TypeError`. It may
  return `ToReturn` and `AgreementChallenges` as well as `Transacted`, `ToApprove` and `Declined`, and `agree` may
  return `AgreementChallenges`.
- **Breaking.** `Next` is `Next(next, summary, h)` (was `Next(next, h)`).
- **Breaking.** A payment `transact`, `confirm` or `finish` builds is held to its pairing's ceiling, 600 seconds unless
  `ceilings` raises it: one that stays payable longer is declined `past-ceiling`, and a form that signs no end, such as
  a delegation or a card checkout, `no-end`. `x402/exact/eip155/gateway-batched` and `mpp/charge/usdc/gateway` are
  declined `floor-missing` unless `inputs` holds the floor inputs `FLOOR_INPUTS` names for them.
- **Breaking.** The gate parses the ATR and declines bytes that are not one JSON text both languages read alike
  (`atr-malformed`); where the ATR's `x402` slot lists `accepts`, or its `mpp` slot `challenges`, declines an option
  they do not hold (`option-not-in-atr`); where the `x402` slot commits to a request, declines another
  `resource_request` (`request-mismatch`); and declines a request it has no summary for (`summary-missing`).
- **Breaking.** An agreement payment is built and checked as the act `agreement`: on `x402/exact/eip155/eip3009`,
  `x402/exact/eip155/permit2`, `x402/exact/casper` and `x402/exact/starknet` it carries the agreement's own value of H
  in place of H, as `@integraledger/lcp` 0.6.0 defines it. Check one with `check(..., act="agreement")`.
- **Breaking**, for code that implements a binding. `Binding` carries the registry's coverage and agreement data in
  place of `public_proof`; its `build` takes `act` and its `bound` takes `given`.
- Every binding builds and reads its pairing as `@integraledger/lcp` 0.6.0 does.

### Removed

- **Breaking.** The bindings of the pairings `@integraledger/lcp` 0.6.0 retired: `MPP_CHARGE_HEDERA`,
  `MPP_CHARGE_STELLAR`, `MPP_CHARGE_TEMPO_MEMO`, `MPP_CHARGE_TEMPO_PUSH`, `MPP_SESSION_HEDERA`, `MPP_SESSION_SOLANA`,
  `X402_EXACT_LNBTC`, `X402_EXACT_LNBTC_INVOICE_NAMED` and `X402_EXACT_STELLAR`.
- `Binding.public_proof`.

Earlier releases are recorded in the repository's history.
