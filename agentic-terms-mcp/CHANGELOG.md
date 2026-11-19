# Changelog

Every notable change to `@integraledger/terms-mcp`, which is released with `@integraledger/terms` under the same
version. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The package is at 0.x: a minor
release may change the tools, their arguments and their results, so pin the exact version. A change a caller must make
is marked **Breaking**; [Upgrading](https://github.com/IntegraLedger/integra-agentic-terms/blob/main/docs/upgrading.md)
shows each call before and after.

## [Unreleased]

### Changed

- `atr_transact` resolves each agreement option's served names against the ATR's bytes as the gate does: an option
  naming a slot that is not the ATR's binding slot, or an index past the charge options that slot holds, is declined
  `offer-unreadable` with `return/serves-malformed`.

## [0.5.1] - 2026-11-18

### Added

- `act` on `atr_confirm` and `atr_finish`: `"agreement"` builds and completes the agreement payment, so an agent with
  no host signer pays an agreement by hand on every pairing whose payment can be one, `x402/exact/eip155/eip3009`,
  `x402/exact/eip155/permit2`, `x402/exact/casper` and `x402/exact/starknet` among them; `"payment"` is the default.

### Changed

- `atr_transact`, `atr_agree` and `atr_channel_within`, which sign and send payments, are annotated
  `destructiveHint: true`, so a host that asks before a destructive tool runs asks before these. They stay open-world.
- A receipt the agreement URL answers to the first, unpaid request carries `unpaid: true` wherever a tool returns it
  (`atr_agree`'s `receipt`, `atr_transact`'s `agreement`): no agreement payment was made or read for it.

### Fixed

- The server drops from a tool's `inputs` every floor input the gate's `FLOOR_INPUTS` names for the pairing, as the
  profile's rule 16 states: `mpp/charge/usdc/gateway`'s `sourceNetwork`, `burnIntentExpirationHeight` and
  `withdrawalDelay` as well as `x402/exact/eip155/gateway-batched`'s `minValiditySeconds`. A host that serves a Gateway
  burn intent answers its three inputs through `floors`; without them it is declined `floor-missing`.
- `atr_confirm`'s `agreement-failed` for a receipt of another form, or for another H, says what it checked: the
  receipt's `atrHash`, `agreed` and string `network` and `transaction`. It no longer says the receipt is not a recorded
  agreement: the tool reads no agreement.
- `atr_agree` holds the agreement payment to its summary and its pairing's ceiling, as `atr_transact` does, the host's
  `ceilings` raising it.

## 0.5.0 - 2026-11-18

Takes `@integraledger/terms` 0.5.0 and `@integraledger/lcp` 0.6.0. Every 0.4.x agent and host changes something: the
entries marked **Breaking** say what.

### Added

- `atr_confirm` returns `summary` beside `request`, and `atr_finish` returns `summary` beside `next`: every authority
  signing that request grants (terms' profile `buyer-gate.md`, rule 13).
- `atr_check` takes `act`: `"agreement"` for an agreement payment, `"payment"` by default.
- `atr_transact` takes `legalContext`, the first response's return value. Where the seller's first response offers only
  the agreement, `atr_transact` pays the agreement and returns `agreement`, `legalContext` and `charge`, signing no
  charge (the protocol package's profile `legal-context-return.md`).
- `atr_transact` and `atr_agree` return `agreementChallenges`, signing nothing, where the agreement URL offers only MPP
  agreement challenges, for the agent's own MPP client to pay.
- `createBuyerServer` takes `ceilings`, which raises a pairing's ceiling, and `floors`, which answers the floor a
  rail's payment service serves. The type `Floors` is exported.
- The decline codes `not-approved`, `atr-malformed`, `option-not-in-atr`, `request-mismatch`, `summary-missing`,
  `past-ceiling`, `no-end` and `floor-missing`.
- Pairings: `ap2/checkout-mandate/x402`, `card/mastercard-agent-pay`, `card/visa-vic`, `mpp/charge/lcp/hedera`,
  `mpp/charge/solana/unsponsored`, `mpp/charge/tempo/split-memo`, `mpp/charge/tempo/split-memo/push`,
  `mpp/session/hedera/stock`, `mpp/session/solana/memo`, `mpp/session/solana/stock`, `mpp/session/xrpl/stock`,
  `mpp/subscription/solana`, `spend-permissions/eip155`, `ucp/checkout/agent-signed`, `x402/exact/cardano/lock`,
  `x402/exact/eip155/gateway-batched`, `x402/exact/lnbtc/payment-hash`, `x402/exact/stellar/precondition` and
  `x402/upto/xrpl`.

### Changed

- **Breaking.** `atr_confirm` and `atr_transact` require `resourceRequest`, the request the seller's 402 answered: over
  HTTP `{method, target, body, headers?}`, `target` in origin form and `body` as base64; over MCP `{name, arguments?}`.
  Where the ATR's `x402` slot commits to a request, any other is declined `request-mismatch`. A call without it fails
  the tool's input schema.
- **Breaking.** `atr_transact` signs only what the agent approved. Before each signing it returns `approve`,
  `{ agreement?, signings }`, and signs nothing; called again with the same arguments and `approved` set to that
  `approve`, unchanged, it signs a signing only where it equals one of `approved.signings` in RFC 8785 form. In 0.4.x
  it signed on the first call, and `approve` and `approved` were the agreement payment alone: such an `approved` now
  fails the input schema.
- **Breaking.** A payment `atr_confirm`, `atr_finish` or `atr_transact` builds is held to its pairing's ceiling, 600
  seconds unless the host raises it with `ceilings`: one that stays payable longer is declined `past-ceiling`, and a
  form that signs no end, such as a delegation or a card checkout, `no-end`. The binary takes no `ceilings`.
- **Breaking.** The two rails whose payment service serves a floor need it. `x402/exact/eip155/gateway-batched` is
  declined `floor-missing` unless the host's `floors` answers its `minValiditySeconds`, which the server drops from a
  tool's `inputs`. `mpp/charge/usdc/gateway` is declined `floor-missing` unless its `sourceNetwork`,
  `burnIntentExpirationHeight` and `withdrawalDelay` are given, by `floors` or, in this version, by a tool's `inputs`.
- **Breaking.** The gate parses the ATR and declines bytes that are not one JSON text both languages read alike
  (`atr-malformed`); where the ATR's `x402` slot lists `accepts`, or its `mpp` slot `challenges`, declines an option
  they do not hold (`option-not-in-atr`); and declines a request it has no summary for (`summary-missing`).
- **Breaking.** An agreement payment is built and checked as the act `agreement`: on `x402/exact/eip155/eip3009`,
  `x402/exact/eip155/permit2`, `x402/exact/casper` and `x402/exact/starknet` it carries the agreement's own value of H
  in place of H, as `@integraledger/lcp` 0.6.0 defines it. `atr_confirm` and `atr_finish` build the payment for the
  resource, so an agreement paid by hand through them is accepted only on the x402 pairings whose agreement payment
  carries H itself.
- **Breaking.** The peer `@integraledger/lcp` is `~0.6.0` (was `~0.5.1`), and Node.js `>=24.22.1` (was `>=24`).
- `atr_agree` and `atr_transact` pay only an agreement option the charge's pairing can follow, by its `agreementOn` in
  the protocol package's registry.
- `atr_finish` returns `next` only once it has a summary and is within the pairing's ceiling.
- Every pairing is built and read as `@integraledger/lcp` 0.6.0 builds and reads it.

### Removed

- **Breaking.** The pairings `@integraledger/lcp` 0.6.0 retired, which the tools' `pairing` argument now refuses:
  `mpp/charge/hedera`, `mpp/charge/stellar`, `mpp/charge/tempo/memo`, `mpp/charge/tempo/push`, `mpp/session/hedera`,
  `mpp/session/solana`, `x402/exact/lnbtc`, `x402/exact/lnbtc/invoice-named` and `x402/exact/stellar`.

Earlier releases are recorded in the repository's history.
