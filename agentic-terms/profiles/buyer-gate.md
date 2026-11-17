**terms profile `buyer-gate`: what the buyer gate checks before anything is signed, the decline each check answers, and the names of its arguments.**

The buyer gate of `@integraledger/terms` (TypeScript) and `integraledger-terms` (Python) pays a seller's offer only after it has compared the ATR the offer names with what the buyer is about to sign. This profile fixes, for both languages alike: the checks the gate makes before anything is signed, in order; the decline code each check answers; the approval callback the one-call function `transact` requires, with its argument and its answer; the request argument, the buyer's own request; the ceiling on how long a signed payment stays payable; the inputs that carry a floor a payment service serves; and what `transact` returns after it pays an agreement. "The gate" is `transact` and `confirm`, which share every check up to the signing request; `transact` alone calls the approver and the signer. A decline is a value, `{decline: {code, detail}}` in TypeScript and `Declined(code, detail, moved)` in Python, never a thrown error: nothing the seller serves, and nothing the approver answers, makes the gate throw. The vectors are `vectors/buyer-gate.json` (rule 17).

## The arguments

1. **`transact`, `confirm` and `finish` take these members as well as what they take today**, by these names:

   | Member | TypeScript | Python | Required | Form |
   | --- | --- | --- | --- | --- |
   | the approval callback | `approver`, in `transact`'s options | `approver=`, keyword of `transact` | yes, in `transact` | rule 11 |
   | the buyer's own request | `resourceRequest`, in `transact`'s and `confirm`'s options | `resource_request=`, keyword of both | yes, in both | rule 2 |
   | the raised ceilings | `ceilings`, in the options of all three | `ceilings=`, keyword of all three | no | rule 8 |
   | a served floor | in `inputs`, by the name rule 9 gives | in `inputs`, by the same name | where rule 9 names one | rule 9 |
   | the first response's return value | `legalContext`, in `transact`'s options | `legal_context=`, keyword of `transact` | no | rule 12 |
   | the payment chosen | `chosen`, in `transact`'s options | `chosen=`, keyword of `transact` | no | `confirm`'s `chosen`, unchanged |

   In TypeScript the options object is each function's last argument: `transact(doc, binding, signer, fetch, options)`, required, holding `approver` and `resourceRequest` and the optional `inputs`, `ceilings`, `legalContext`, `agreementSigner`, `approved`, `signal` and `chosen`; `confirm(doc, binding, account, fetch, options)`, required, holding `resourceRequest` and the optional `inputs` and `ceilings`, `confirm`'s `inputs` moving into it; and `finish(bytes, chosen, signature, binding, options?)`, holding the optional `ceilings`. In Python they are keyword-only: `transact(doc, binding, signer, fetch, *, approver, resource_request, inputs=None, ceilings=None, legal_context=None, agreement_signer=None, approved=None, signal=None, chosen=None)`, `confirm(doc, binding, account, fetch, *, resource_request, inputs=None, ceilings=None)` and `finish(atr_bytes, chosen, signature, binding, *, ceilings=None)`. Options that hold another member, an `approver` that is not callable, a `resourceRequest` that is not an object (in Python, not a mapping), `ceilings` not of rule 8's form, a `legalContext` that is not a string, or a `chosen` that is not an object of `confirm`'s `chosen` form for the pairing are declined `no-payable-option` with the detail `<namespace>/input-malformed`, as malformed `inputs` are, before anything is fetched or signed.

2. **The request argument** is the request the buyer is about to pay, the one the seller's offer answered, in the form lcp's request commitment reads it (lcp profile `x402-request-commitment.md`). Over HTTP it is lcp's `HttpRequest`, `{method, target, body, headers?}`: the method token and the request-target as received, the body's bytes (a `Uint8Array`; in Python `bytes`), and, where the request has header fields, `headers`, each field's name with its value or its lines in the order received (lcp's `HeaderFields`). Over MCP it is lcp's `ToolCall`, `{name, arguments?}`: the `tools/call` request's `params.name` and `params.arguments`. TypeScript names the union `ResourceRequest`, `HttpRequest | ToolCall`, lcp's own types from `@integraledger/lcp/x402`. Python names two `TypedDict`s, `HttpRequest` and `ToolCall`, with the same member names, a member the request lacks being absent from the mapping, and the union `ResourceRequest`. The gate reads its members only where rule 7 compares them.

## The checks, in order

3. **The gate makes these checks in this order** and answers the first that fails with its code. Each answers before the signer is called for the signing it concerns.

   | Order | Check | Decline |
   | --- | --- | --- |
   | 1 | The binding names a pairing the gate has a buyer piece for | `pairing-not-supported` |
   | 2 | The arguments are of rule 1's form | `no-payable-option`, detail `<namespace>/input-malformed` |
   | 3 | Where rule 9 names a floor input for the pairing, `inputs` holds it in its form | `floor-missing` |
   | 4 | The offer reads, an option is payable by the account, the link is `https`, the ATR is fetched within bounds, and SHA-256 of the bytes served is the advertised H | `offer-unreadable`, `no-payable-option`, `link-not-https`, `atr-unfetchable`, `atr-too-large`, `hash-mismatch` |
   | 5 | The bytes parse (rule 5) | `atr-malformed` |
   | 6 | Where the ATR's binding slot holds the options offered, it holds the option chosen (rule 6) | `option-not-in-atr` |
   | 7 | Where the ATR's binding slot holds a request commitment, it is the buyer's request's (rule 7) | `request-mismatch` |
   | 8 | A pairing whose payment is paid after its agreement has an agreement offered | `agreement-not-offered` |
   | 9 | The pairing builds the payment with the H the gate computed | `offer-unreadable` |
   | 10 | The gate computes the summary of the request handed to the signer (rule 13) | `summary-missing` |
   | 11 | The signed payment would stay payable no longer than the pairing's ceiling (rule 8) | `past-ceiling`, `no-end` |
   | 12 | The approver approves the signing (rule 11), in `transact` alone | `not-approved` |

   `confirm` makes checks 1 to 11 and returns the signing request; `transact` makes all twelve and calls the signer only after the twelfth. A payment signed in several steps makes checks 10 to 12 again on each later step's request before that step is signed; `finish`, which returns a later step's request to a caller that signs it, makes checks 10 and 11 on it before returning it, and returns its summary with it. Given `chosen`, `transact` builds the payment from it, as `finish` does, rather than choosing anew with its clock and a new reference, so the request it asks the approver about is the one `confirm` returned for it. The agreement payment is checked as rule 12 states.

## Decline codes

4. **The codes this profile adds** to those the gate returned before it. Each is a value of `DeclineCode` in both languages.

   | Code | Returned when | Signer called? |
   | --- | --- | --- |
   | `not-approved` | The approver answered anything but `true`, threw (in Python, raised) or rejected, for the signing it was asked about (rule 11). | Not for the signing declined; an earlier step of the same payment, or the agreement payment, may have been signed |
   | `atr-malformed` | The ATR's bytes do not parse by rule 5. | No |
   | `option-not-in-atr` | The ATR's binding slot holds the options offered, and none of them is the option chosen (rule 6). | No |
   | `request-mismatch` | The ATR's binding slot holds a request commitment that is not the buyer's request's, or one of no form lcp writes (rule 7). | No |
   | `summary-missing` | The request handed to the signer is of a kind rule 13's table fills no row for, so the gate cannot show it; nothing is signed unshown. | No |
   | `past-ceiling` | The signed payment would stay payable longer than the pairing's ceiling (rule 8). | No |
   | `no-end` | The form signs no end, and `ceilings` does not map the pairing to `"no-end"` (rule 8). | No |
   | `floor-missing` | The pairing's rail has a served floor, and `inputs` does not hold its input in its form (rule 9). The detail is the input's name, such as `minValiditySeconds`. | No |

## The rules

5. **The parse.** The gate parses the ATR's bytes as they were fetched, the bytes it hashed, and never a value re-serialised from them, and it refuses exactly what lcp's `assemble` refuses in a party's bytes, its check 8 (`core/content-not-json`), so that no ATR lcp writes is one the gate declines. It declines `atr-malformed` bytes that:
   - are not UTF-8;
   - begin with a byte-order mark, the bytes `EF BB BF`, which a sender must not add (RFC 8259, section 8.1);
   - are not exactly one JSON text by RFC 8259's grammar (section 2), whitespace around it apart, as `NaN`, `Infinity` and `-Infinity` are not;
   - nest arrays and objects past 64 levels, lcp's `MAX_JSON_DEPTH`;
   - hold an object in which a member name repeats, the names compared after their escapes are decoded (RFC 8259, section 7), so that `"a"` and `"\u0061"` are one name, as are `"é"` and `"\u00e9"` (RFC 7493, section 2.3);
   - hold a number whose value rounds to infinity as an IEEE 754 double (RFC 7493, section 2.2), such as `1e400` or `1.7976931348623159e308`;
   - hold an integer, a number written with neither a fraction nor an exponent, outside −(2^53 − 1) to 2^53 − 1 (RFC 7493, section 2.2), which JavaScript rounds and Python keeps.

   So the two languages read one text alike: `9007199254740991` and `-9007199254740991` parse, and `9007199254740992` and `-9007199254740992` do not. Python's `json.loads` takes `NaN`, `Infinity` and `-Infinity`, reads a number past the largest double as infinity, keeps an integer past 2^53 − 1 exactly and keeps the last of a repeated name; JavaScript's `JSON.parse` keeps the last of a repeated name and rounds such an integer to a double: neither alone is the parse. The parse refuses nothing else, an escaped lone surrogate and a text whose value is not an object among what it takes, and it judges no member of the ATR.

6. **The option chosen and the binding slot.** The ATR's binding slot is its member named by the pairing's protocol, as lcp's `tie` writes it, and it holds the options offered where it has the member that lists them: `accepts` in `x402`, `challenges` in `mpp`, `options` in `acp`, `ap2`, `card` and `ucp`, and `paymentOptions` in `ack`. Where it does, the gate declines `option-not-in-atr` an option chosen that equals none of that list's members, compared as canonical JSON (RFC 8785) in the form the slot holds it, the pairing's own: an option as the pairing's `unplaced` gives it, where the pairing has one, before H is placed (Solana's `extra.memo`, TON's `extra.forwardPayload`), and otherwise as offered; an MPP challenge by its bound members as lcp's `issuedDigest` reads them, without its `id` and lcp's `opaque` members, which carry H, each member of `challenges` read the same way. A listing member that is not a list holds no option. Where the slot is absent, is not an object, or has no such member, the gate makes no comparison. The comparison holds the option to the binding H commits to, and judges no term. Every agreement option, an x402 one and an MPP agreement challenge alike, is held by the approval alone (rule 11): the gate compares no agreement option with the binding slot.

7. **The buyer's request and the binding slot.** Where the binding slot is `x402` and holds a `request` member, the gate compares it with `resourceRequest`. A member of exactly the members `method`, `path`, `query` and `bodyDigest`, with `headers` where the resource server named header fields, is the commitment over HTTP: the gate computes lcp's `requestCommitment` of `resourceRequest` with the names its `headers` lists, in that order, and none where it has no `headers`. A member of exactly `tool` and `argumentsDigest` is the commitment over MCP: the gate computes lcp's `toolCallCommitment` of `resourceRequest`. The gate declines `request-mismatch` where the commitment it computes does not equal the slot's as canonical JSON (RFC 8785); where lcp refuses `resourceRequest`, the detail then being lcp's code (`x402/request-target-invalid`, `x402/request-header-invalid`, `x402/tool-call-malformed`, `x402/request-too-large`); and where the `request` member is of neither form. Where the slot holds no `request` member, as on MPP, whose slot holds the challenges alone, the gate makes no comparison, and the request is held by the approval alone. The comparison holds the request to the binding H commits to, and judges no term.

8. **The ceiling.** The gate declines an option whose signed payment would stay payable past the pairing's ceiling. How long a signed payment stays payable, its window, is read from the request handed to the signer, by the summary's `validity` (rule 13): for a deadline in seconds, the deadline less the time the gate reads from its clock; for a deadline signed as a height, a slot, a round, a ledger or an epoch, the deadline less the start the request signs, where it signs one, and otherwise less the height the caller gave the build, that count of units times the chain's pace below; and where the payer signs no deadline and the rail itself bounds the payment, the pairing's `read.life` in lcp's registry, that bound, in seconds or, in another unit, times the pace. The pace of a chain is stated once, here, with its source, read on 2026-11-17:

   | Chain | Unit | Seconds per unit | Source |
   | --- | --- | --- | --- |
   | Algorand | round | 2.82 | "Algorand confirms blocks every 2.82 seconds on average", https://dev.algorand.co/concepts/transactions/blocks/ |
   | Cardano, its networks named in the `cardano` or the `cip34` namespace (CIP-34, *Chain ID Registry*, `cip34:NetworkId-NetworkMagic`, https://cips.cardano.org/cip/CIP-0034; lcp profile `x402-exact-cardano.md`, rule 7) | slot | 1 | "each slot lasts for one second", https://docs.cardano.org/about-cardano/learn/cardano-node |
   | NEAR | block | 0.6 | "Typical block time is around 600ms", https://docs.near.org/integrations/blocks-and-finality |
   | Polkadot | block | 6 | "six-second block times are now the default", https://developers.polkadot.com/reference/polkadot-hub/consensus-and-security/relay-chain/ |
   | Solana | block | 0.3 | `DEFAULT_MS_PER_SLOT`, "The SDK's default expected duration of a slot (300 milliseconds)", `solana-clock` 4.0.0, https://docs.rs/solana-clock/latest/solana_clock/constant.DEFAULT_MS_PER_SLOT.html |
   | Stellar | ledger | 5 | the protocol package's own conversion, the authorization entry's expiration being "the current ledger plus `ceil(maxTimeoutSeconds / 5)`" (lcp profile `x402-exact-stellar-precondition.md`, rule 5); and a Stellar RPC's retention, "a stock default of 120960 ledgers (about 7 days, depending on ledger cadence)", 604,800 seconds over 120,960 ledgers, https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/getEvents |
   | Sui | epoch | 86,400 | "an epoch is about 24 hours", https://docs.sui.io/concepts/sui-architecture/epochs |
   | XRP Ledger | ledger | 5 | "new ledger versions usually close about every 3 to 5 seconds", the range's upper end, https://xrpl.org/docs/concepts/ledgers/ledger-close-times |
   | an EVM network, for a Circle Gateway burn intent's `maxBlockHeight` | block | 604,800 / `withdrawalDelay` | the Gateway Wallet's withdrawal delay is 7 days, 604,800 seconds, which its `withdrawalDelay` counts in that network's blocks, https://developers.circle.com/gateway/concepts/technical-guide |

   On the XRP Ledger the request signs its deadline, `LastLedgerSequence`, which lcp's XRPL builds take from the caller as the input `lastLedgerSequence`, and signs no start, so the caller gives the start too: `ledgerIndex` in `inputs`, the index of the validated ledger it read, as rippled names it (`ledger_index`), a non-negative safe integer. The window is `LastLedgerSequence` less `ledgerIndex`, times the XRP Ledger's pace. A signing on the XRP Ledger whose `inputs` lack `ledgerIndex` in that form, a payment or the agreement a pairing on that ledger follows, is declined `no-payable-option` with `xrpl/input-missing` at check 11, after the hash is compared and before it is signed.

   A pairing's ceiling is 600 seconds; on a rail rule 9 names, the served floor plus the service's margin, the 600 seconds never being that rail's ceiling; and, where `ceilings` names the pairing, the larger of that and the value given. `ceilings` maps a pairing id to a positive safe integer of seconds, or to `"no-end"`, which lifts that pairing's ceiling and admits a form that signs no end; an id the call does not pay is not read. A payment payable longer than its pairing's ceiling is declined `past-ceiling`. A form that signs no end, a delegation or a transaction with no validity, is past every ceiling, and is declined `no-end` unless `ceilings` maps its pairing to `"no-end"`. TypeScript names the map's type `Ceilings`, `{ readonly [pairing: string]: number | "no-end" }`; Python names it `Ceilings`, `Mapping[str, int | Literal["no-end"]]`, in which a `bool` is no integer.

9. **The served floor.** On a rail whose payment service refuses a shorter validity, the caller reads the floor that service serves and gives it in `inputs`, under the name lcp's build takes, so that the value the gate holds the payment to is the one the build signs with; the gate reads no service of its own. Where `inputs` lacks it, or holds it in another form, the gate declines `floor-missing`, whose detail is the input's name, before it reads the offer.

   | Pairing | Input | Its form | The service's margin | The ceiling |
   | --- | --- | --- | --- | --- |
   | `x402/exact/eip155/gateway-batched` | `minValiditySeconds` | a positive safe integer: the `minValiditySeconds` Circle Gateway's `/supported` serves for the network | 100 seconds, Circle's (`@circle-fin/x402-batching` 4.0.0, `src/constants.ts:39-49`) | `minValiditySeconds` plus 100 seconds |
   | `mpp/charge/usdc/gateway` | `sourceNetwork`, `burnIntentExpirationHeight` and `withdrawalDelay` (rule 14) | `sourceNetwork`, the CAIP-2 network the burn intent spends from, a non-empty string; `burnIntentExpirationHeight`, the decimal string Circle Gateway's `GET /v1/info` serves for that network; and `withdrawalDelay`, that network's Gateway Wallet's `withdrawalDelay()`, in blocks, a decimal string; each decimal string below 2^256 | 100 seconds counted in that network's blocks at the pace of the delay's 7 days: `withdrawalDelay` × 100 / 604,800, rounded up | the burn intent's `maxBlockHeight` at `burnIntentExpirationHeight` plus the margin, in that network's blocks |

   Both languages export the table's inputs as `FLOOR_INPUTS`, a map from each pairing to the names of its floor inputs.

   On `x402/exact/eip155/gateway-batched` lcp's build signs `validBefore` at the clock plus the larger of the option's `maxTimeoutSeconds` and `minValiditySeconds` plus 100, so a stock offer whose `maxTimeoutSeconds` is no larger than that is within the ceiling, and one larger is declined `past-ceiling` unless `ceilings` raises it.

10. **What a check reads.** Checks 3 to 11 read the seller's offer, the ATR's bytes, the request built for the signer and the caller's arguments, and nothing else: no service, no ledger and no clock but the gate's own. Each bounds what it reads by the bounds the gate and lcp already hold (the ATR's 1 MiB, lcp's `MAX_REQUEST_BYTES` for a request).

11. **The approval.** `transact` requires `approver`, a function the caller gives. For each signing, once every check of rule 3 on it has passed and before the signer is called for it, the gate calls the approver once, with one argument, `ToSign`:

    | Member | TypeScript | Python | Holds |
    | --- | --- | --- | --- |
    | the act | `act` | `act` | `"payment"`, the payment for the resource, or `"agreement"`, the agreement payment: lcp's names for the two acts under one H |
    | the pairing | `pairing` | `pairing` | the id of the pairing whose build made the request |
    | the signing request | `request` | `request` | the request the signer will be handed, as the signer is handed it: `SigningRequest`, in Python a `dict` |
    | the summary | `summary` | `summary` | `Summary`, rule 13 |
    | the step | `step` | `step` | `SigningStep`: `index`, counted from 0, and `count`, the number of signings the payment takes, at most two today |

    The approver answers `true` (in Python `True`) to approve, or a promise of it (in Python an awaitable). Any other answer, `false`, `"yes"` and `1` among them, a thrown error (in Python a raised exception) or a rejected promise approves nothing, and the gate declines `not-approved` without calling the signer for that signing. What the approver does to the values it is handed changes nothing the signer is handed. TypeScript names the function's type `Approver`, `(toSign: ToSign) => boolean | Promise<boolean>`; Python names it `Approver`, `Callable[[ToSign], bool | Awaitable[bool]]`.

12. **The agreement payment, and the return.** The agreement payment is approved like every other signing: it is held to its own pairing's ceiling (rule 8) and asked of the approver with `act` `"agreement"` before it is signed. Where a pairing is paid after its agreement (lcp profile `legal-context-return.md`), the first response offers the agreement and no charge option; `transact` chooses the charge from the options the ATR's binding slot holds, by the agreement option's `serves` (its `extra.legalContextServes` on x402, its `opaque` member `legalContextServes` on MPP): it pays an agreement option whose `serves` names a charge the account can pay, and that charge, named `<slot>/<i>` as the profile names it, is the one chosen. It pays the agreement and ends at the agreement's receipt, signing no charge, and returns `ToReturn`:

    | Member | TypeScript | Python | Holds |
    | --- | --- | --- | --- |
    | the agreement's receipt | `agreement` | `agreement` | the `AgreementReceipt` the agreement resource answered |
    | the return header | `legalContext` | `legal_context` | the `Legal-Context` value the caller sends when it repeats its request: H's LCP string, with `rv`, the return value, where the first response carried one (lcp profile `legal-context-return.md`, rules 2 and 4) |
    | the charge chosen | `charge` | `charge` | the chosen charge option's name, `<slot>/<i>`, such as `x402/0` |
    | the ATR's bytes | `bytes` | `atr_bytes` | the bytes the gate compared |
    | H | `h` | `h` | their SHA-256 |

    The return value reaches the gate as an input the caller copies from the first response: `legalContext` (in Python `legal_context`), that response's `Legal-Context` header value as received over HTTP, or its `_meta["com.integraledger.lcp/legal-context"]` over MCP; absent where the response carried none. A value lcp's `fromLegalContextHeader` refuses is declined `offer-unreadable` with lcp's code (`return/header-malformed`), and one whose H is not the ATR's `hash-mismatch`. The caller repeats its request with the returned `legalContext` and calls `transact` again with the second response, which offers the charge; the agreement being recorded, that call pays the charge as any other. The exchange `transact` already has, which returns the agreement payment as `approve` and pays it once called again with that payment as `approved`, stays alongside the approver: an `approved` agreement payment is still asked of the approver before it is signed.

13. **The summary**, `Summary`, names every authority the signature grants. Its shape is closed: it holds these members and no other, each present where the form has what it names and otherwise absent in TypeScript and `None` in Python. Every integer in it is a decimal string, every amount is in the asset's base units, and every time is in Unix seconds, but a `validity` whose `unit` names another.

    | Member | TypeScript | Python | Holds |
    | --- | --- | --- | --- |
    | the amount | `amount` | `amount` | what the payee is paid, where the payment pays a fixed amount |
    | the maximum | `maximum` | `maximum` | the most the payee may charge, where the payee names the charge (`upto`) |
    | the payees | `payees` | `payees` | every payee, each a `Payee`, `{account, amount}`: its account as the form names it, and its split, its part of the amount or of the maximum; always present |
    | the period | `period` | `period` | the period, in seconds (a subscription's key authorization, a Spend Permission) |
    | the limit per period | `limitPerPeriod` | `limit_per_period` | the most that may move in one period |
    | the end | `end` | `end` | when the authority ends (a subscription's key authorization, a Spend Permission) |
    | the operator | `operator` | `operator` | the operator (`auth-capture`) |
    | the authorization's expiry | `authorizationExpiry` | `authorization_expiry` | when the authorization expires (`auth-capture`) |
    | the refund's expiry | `refundExpiry` | `refund_expiry` | when the refund expires (`auth-capture`) |
    | the deposit | `deposit` | `deposit` | the deposit (a session or a channel) |
    | who may close | `closableBy` | `closable_by` | the accounts that may close it (a session or a channel) |
    | a delegation's grant | `grant` | `grant` | what a delegation grants, as JSON |
    | the asset | `asset` | `asset` | the asset, as the form names it; always present |
    | the network | `network` | `network` | the network, as a CAIP-2 id; always present |
    | the validity | `validity` | `validity` | a `Validity`, `notBefore`, `notAfter` and `unit` (in Python `not_before`, `not_after` and `unit`): from and until when the signed payment is payable, each `null` (in Python `None`) where the form signs none, in `unit`, `"seconds"` for Unix seconds or the unit rule 8's pace table names; always present |
    | the ATR's bytes | `atr` | `atr` | the bytes the gate hashed, parsed and compared; always present |

    `Payee` and `Validity` hold only the members named here. In Python, `ToSign`, `SigningStep`, `Summary`, `Payee`, `Validity` and `ToReturn` are frozen dataclasses with these member names.

    The gate computes the summary from the request handed to the signer, never from the option or the build's inputs, so a request that grants more than the offer is shown granting it. Where the request names no network, the summary's `network` is the signer's account's, the CAIP-2 network of its CAIP-10 `account`, which check 4 holds equal to the option's; a request that names a network shows that one, so a mismatch is visible. A later step of a payment signed in steps, such as a voucher after a session's or a channel's opening, which names only the channel, is shown with the payees, asset and network of the step that opened the channel, which the gate hands its summary beside the request; a later step whose channel is not the one that step opened has no summary. The table below has a row per pairing, a row keyed by a request where pairings share one, and names the signed field that fills each member; in it `m` is the request's `typedData.message` and `d` its `typedData.domain`, a member the form does not have is "none", and a row with no cells filled is filled with its pairing's buyer piece, never guessed. Until its row is filled, a pairing's request is declined `summary-missing` (rule 3, check 10).

    | Request, and its pairings | `amount` or `maximum` | `payees` | `asset` | `network` | `validity` | Other members |
    | --- | --- | --- | --- | --- | --- | --- |
    | `eip712`, `TransferWithAuthorization` (EIP-3009): `x402/exact/eip155/eip3009` | `amount`: `m.value` | `m.to`, with `m.value` | `d.verifyingContract` | `eip155:` and `d.chainId` | `m.validAfter` to `m.validBefore`, seconds | none |
    | `eip712`, `PermitWitnessTransferFrom` (Permit2), witness `{to, validAfter}`: `x402/exact/eip155/permit2` | `amount`: `m.permitted.amount` | `m.witness.to`, with `m.permitted.amount` | `m.permitted.token` | `eip155:` and `d.chainId` | `m.witness.validAfter` to `m.deadline`, seconds | none |
    | `eip712`, `PermitWitnessTransferFrom` (Permit2), witness `{to, facilitator, validAfter}`: `x402/upto/eip155/permit2` | `maximum`: `m.permitted.amount` | `m.witness.to`, with `m.permitted.amount` | `m.permitted.token` | `eip155:` and `d.chainId` | `m.witness.validAfter` to `m.deadline`, seconds | none |
    | `erc7710`: `x402/exact/eip155/erc7710`, `x402/exact/eip155/erc7710-salt` | `amount`: `amount` | `payTo`, with `amount` | `token` | `eip155:` and `chainId` | none to none: a delegation signs no end | `grant`: `{token, payTo, amount}` |
    | `eip712`, `TransferWithAuthorization` (EIP-3009): `mpp/charge/evm/authorization`, `mpp/charge/usdc/evm` | `amount`: `m.value` | `m.to`, with `m.value` | `d.verifyingContract` | `eip155:` and `d.chainId` | `m.validAfter` to `m.validBefore`, seconds | none |
    | `evm-call` whose `call` holds `to` and `data` alone, `data` an ERC-20 `transfer(address,uint256)`: `mpp/charge/evm/hash`, `mpp/charge/evm/transaction` | `amount`: the transfer's amount, `data`'s second word | the transfer's recipient, `data`'s first word, in lowercase hex, with the amount | `call.to` | `eip155:` and `chainId` | none to none: a transaction signs no end | none |
    | `tempo-key-authorization`, `a` its `authorization`, whose RLP's keccak-256 is the `digest` the root key signs, with one limit and every allowed call to that limit's token under the selector `transferWithMemo` (`0x95777d59`) with recipients: `mpp/subscription/tempo` | none | every recipient of `a.allowedCalls`' selector rules, each with `a.limits[0].limit` | `a.limits[0].token` | `eip155:` and `a.chainId` | none to `a.expiry`, seconds; none to none where `a.expiry` is 0, which signs no expiry | `period`: `a.limits[0].period`; `limitPerPeriod`: `a.limits[0].limit`; `end`: `a.expiry`, absent where it is 0; `grant`: `{keyId, limits, allowedCalls}` of `a` |
    | `casper-eip712`, CEP-3009's `TransferWithAuthorization` under CEP-3009's types: `x402/exact/casper` | `amount`: `m.value` | `m.to`, with `m.value` | `d.contract_package_hash` | `d.chain_name`, the network's CAIP-2 id | `m.validAfter` to `m.validBefore`, seconds | none |
    | `starknet-snip12`, SNIP-9's `OutsideExecution` under SNIP-12 revision 1, whose `m.Calls` is one call `c` of the selector `transfer` with three calldata felts: `x402/exact/starknet` | `amount`: `c.Calldata[1]` plus `c.Calldata[2]` times 2^128, the `u256`'s low and high halves | `c.Calldata[0]`, with the amount | `c.To` | `starknet:` and `d.chainId`'s short string | `m["Execute After"]` to `m["Execute Before"]`, seconds | none |
    | `ccd-transfer`: `x402/exact/ccd` | `amount`: `amount` | `toAddress`, with `amount` | `asset` | `network` | none to `expiresBy`, seconds | none |
    | `substrate-call` whose `call` is `batch_all([transfer_keep_alive(assetId, Id(dest), amount), remark_with_event(remark)])` as lcp's `decodeProfileCall` reads it: `x402/exact/polkadot/lcp-assets-remark` | `amount`: `amount` | `dest`, the 32-byte account as `0x` and lowercase hex, with `amount` | `assetId`, in decimal | `network` | none to none, blocks: the call signs no era, which the signer's extrinsic adds | none |
    | `aptos-transaction`, whose transaction the wallet builds from `accepted`, an `exact` option: `x402/exact/aptos` | `amount`: `accepted.amount` | `accepted.payTo`, with `accepted.amount` | `accepted.asset` | `accepted.network` | none to none, seconds: the request names no expiry, which the wallet sets | none |
    | `cardano-transaction`, whose transaction the wallet builds from `accepted`, an `exact` option: `x402/exact/cardano` | `amount`: `accepted.amount` | `accepted.payTo`, with `accepted.amount` | `accepted.asset` | `accepted.network` | none to none, slots: the request names no TTL, which the wallet sets | none |
    | `sui-transaction` whose `expiration` is `"epoch-bounded"`, whose transaction the wallet builds from `accepted`, an `exact` option: `x402/exact/sui` | `amount`: `accepted.amount` | `accepted.payTo`, with `accepted.amount` | `accepted.asset` | `accepted.network` | none to none, epochs: the request names no epoch, which the wallet sets | none |
    | `ack/payment-request` | | | | | | |
    | `acp/checkout/undelegated` | | | | | | |
    | `card/mastercard-agent-pay` | | | | | | |
    | `card/mastercard-vi/autonomous` | | | | | | |
    | `card/mastercard-vi/immediate` | | | | | | |
    | `card/seller-reference` | | | | | | |
    | `card/visa-tap` | | | | | | |
    | `card/visa-vic` | | | | | | |
    | `mpp/charge/card` | | | | | | |
    | `mpp/charge/evm/permit2` | | | | | | |
    | `mpp/charge/lightning` | | | | | | |
    | `mpp/charge/nearintents` | | | | | | |
    | `mpp/charge/stripe` | | | | | | |
    | `mpp/charge/tempo/split-memo` | | | | | | |
    | `mpp/charge/tempo/split-memo/push` | | | | | | |
    | `mpp/charge/usdc/gateway` | | | | | | |
    | `mpp/session/evm` | | | | | | |
    | `mpp/session/hedera/stock` | | | | | | |
    | `mpp/session/lightning` | | | | | | |
    | `mpp/session/solana/stock` | | | | | | |
    | `mpp/session/tempo` | | | | | | |
    | `mpp/session/xrpl/stock` | | | | | | |
    | `mpp/subscription/solana` | | | | | | |
    | `mpp/subscription/stripe` | | | | | | |
    | `ucp/booking/unsigned` | | | | | | |
    | `ucp/checkout/unsigned` | | | | | | |
    | `x402/auth-capture/eip155/eip3009` | | | | | | |
    | `x402/auth-capture/eip155/permit2` | | | | | | |
    | `x402/batch-settlement/cloudflare` | | | | | | |
    | `x402/batch-settlement/eip155` | | | | | | |
    | `x402/batch-settlement/solana` | | | | | | |
    | `x402/exact/cardano/lock` | | | | | | |
    | `x402/exact/eip155/gateway-batched` | | | | | | |
    | `x402/exact/near` | | | | | | |
    | `x402/exact/tron/lcp-trc20-memo` | | | | | | |
    | `x402/exact/tvm` | | | | | | |
    | `solana-message`, token or SOL transfers: `x402/exact/solana`, `mpp/charge/solana`, `mpp/charge/solana/unsponsored`, `mpp/charge/usdc/solana` | `amount`: the sum of the transfers | each `TransferChecked`'s destination token account, or each System `transfer`'s recipient, with its amount | the `TransferChecked`'s mint, or `sol` for a System `transfer`; one asset | the signer's account's network: the request names none | none to none, `block`: the blockhash bounds it for the pairing's `read.life` | none. The message holds only Compute Budget and Memo instructions and these transfers, read with the protocol package's decoder; any other instruction, a durable nonce's `AdvanceNonceAccount` among them, or an account loaded from an address table, gives no summary |
    | `solana-message`, a payment-channels `open`: `x402/upto/solana` | `maximum`: the `open`'s deposit | the `open`'s distribution, each recipient with its basis points of the deposit, the points summing to 10,000; the channel's payee, its third account, with the whole where it names none | the `open`'s mint, its fourth account | the signer's account's network: the request names none | none to none, `block`, as above | `deposit`: the `open`'s deposit. The message holds only Compute Budget and Memo instructions and the one `open` |
    | `solana-session-open`: `mpp/session/solana/memo` | none: the vouchers that charge the channel are signed apart | as the row above | as the row above | the signer's account's network: the request names none | none to none, `block`, as above | `deposit`: the `open`'s deposit. Who may close is the payment-channels program's rule, which the `open`'s bytes do not state |
    | `xrpl-tx`, a `Payment` of XRP: `x402/exact/xrpl`, `mpp/charge/xrpl` | `amount`: `Amount`, in drops | `Destination`, with `Amount` | `XRP`; an issued currency's `Amount`, a decimal value with no base unit, gives no summary | `xrpl:` and `NetworkID` where the transaction sets one; otherwise the signer's account's network: the request names none | none to `LastLedgerSequence`, `ledger` | none. `Flags` is 0, and a member other than those the protocol package writes gives no summary |
    | `xrpl-session-open`: `mpp/session/xrpl` | `amount`: the first claim's drops, its bytes `CLM\0`, the channel the `PaymentChannelCreate` makes, and the drops as a big-endian u64 | `Destination`, with the claim's drops | `XRP` | as the row above | none to `LastLedgerSequence`, `ledger` | `deposit`: `Amount`; `closableBy`: `Account` and `Destination`, the destination at any time and the source once `SettleDelay` has passed (xrpl.org, `PaymentChannelClaim`); `end`: `CancelAfter` plus 946,684,800, in Unix seconds, where set |
    | `algorand-txn`, an asset transfer: `x402/exact/algorand` | `amount`: `aamt`, 0 where absent | `arcv`'s address, with `aamt` | `xaid`, as a decimal | `algorand:` and the first 32 characters of `gh` in URL-safe base64 | `fv` to `lv`, `round` | none. `type` is `axfer`; a `rekey`, `aclose` or `asnd`, or any member an asset transfer does not need, gives no summary |
    | `stacks-contract-call`: `mpp/charge/usdc/stacks` | `amount`: `args.amount` | `args.recipient`, with `args.amount` | `contract` | `stacks:` and `chainId` | none to none: a Stacks transaction signs no expiry | none. `functionName` is `transfer`, `postCondition` `SentEq` and `postConditionMode` `deny`, so the call moves the amount and nothing else |
    | `hedera-body`, a crypto transfer: `x402/exact/hedera`, `mpp/charge/lcp/hedera` | `amount`: the sum of the credits | each row the transfer credits, with its credit | `0.0.0` for HBAR, or the token's id; one asset | the signer's account's network: the request names none | the transaction id's valid start to that plus `transactionValidDuration`, `seconds` | none. The body holds only `transactionID`, `nodeAccountID`, `transactionFee`, `transactionValidDuration`, `memo` and `cryptoTransfer` |
    | `hedera-executor`: `x402/exact/hedera/transfer-executor` | `amount`: `amount` | `payTo`, with `amount` | `asset` | `network` | none to `validBefore`, `seconds` | `grant`: `{executors, asset, payTo, amount}`, the authorization the executor tooling is asked for |
    | `stellar-precondition`, a Soroban authorization's `HashIDPreimage` (`ENVELOPE_TYPE_SOROBAN_AUTHORIZATION`, or its form with the address) whose invocation is one `transfer(from, to, amount)` on a contract with no sub-invocation, `from` and `to` accounts, and the 40-byte `payload` of the signed-payload precondition: `x402/exact/stellar/precondition` | `amount`: the `transfer`'s `amount`, an `i128` | `to`, as its `G…` strkey, with the amount | the contract, as its `C…` strkey | `stellar:pubnet` or `stellar:testnet`: the network whose passphrase's SHA-256 is the preimage's `networkID` | none to the preimage's `signatureExpirationLedger`, `ledger`, the window counted from `currentLedger`, the ledger the caller gave the build | none. The payload is H, then the preimage's `nonce`: a payload whose last 8 bytes are not that nonce, a negative amount, a form with the address whose address is not `from`, or any other invocation gives no summary |
    | `ap2-checkout-mandate`, AP2's closed Checkout Mandate's claims `c`, which commit to `c.checkout_jwt` by `c.checkout_hash`, read only where that is the JWT's hash (the base64url of its SHA-256), the JWT's payload being `p`: `ap2/checkout-mandate`, `ap2/checkout-mandate/x402` | `amount`: the one entry of `p.totals` whose `type` is `total`, its `amount`, in the currency's minor units | `p.merchant.id`, with the amount, where the checkout names a merchant; none where it names none | `p.currency` | the signer's account's network: the request names none | none to none, seconds: the request names no expiry, which the mandate's signer sets | none |
    | `ucp-checkout`, the checkout `k` the mandate issuer signs over: `ucp/checkout/ap2-mandate`, `ucp/booking/ap2-mandate` | `amount`: the one entry of `k.totals` whose `type` is `total`, its `amount`, in the currency's minor units | none: the request names no payee's account | `k.currency` | the signer's account's network: the request names none | none to none, seconds: the request names no expiry | none |
    | `ucp-legal-context`, the member `{type, value}` the platform writes into the request that completes the checkout `k`, beside `k`: `ucp/checkout/agent-signed` | as the `ucp-checkout` row | as that row | as that row | as that row | as that row | none. `type` is `sha256` and `value` is H, `0x` and 64 lowercase hex digits |
    | `acp-allowance`, ACP's allowance `a`: `acp/checkout/delegated` | `maximum`: `a.max_amount`, in the currency's minor units | `a.merchant_id`, with `a.max_amount` | `a.currency` | the signer's account's network: the request names none | none to `a.expires_at`, an RFC 3339 `date-time` (section 5.6), in Unix seconds, a fraction of a second rounded up | none |

14. **The Gateway burn intent's inputs.** `mpp/charge/usdc/gateway`'s floor inputs are the three lcp's build takes, by the names rule 9 gives: `sourceNetwork`, `burnIntentExpirationHeight` and `withdrawalDelay`. The build signs `maxBlockHeight` as `burnIntentExpirationHeight` plus ceil(`withdrawalDelay` × 100 / 604,800), refuses an input absent or malformed, or a sum above 2^256 − 1, `mpp/input-malformed`, and its `complete` refuses a credential whose `sourceNetwork` is another (`mpp/input-malformed`) and a signed burn intent whose `maxBlockHeight` is not the one built (`mpp/max-block-height-changed`) (lcp profile `mpp-charge.md`, rule 8). So the buyer's own Gateway client does not choose `maxBlockHeight`, and the burn intent the gate shows ends at the served floor plus the margin, in the source network's blocks.

15. **The costs, stated.** A seller's terms write a number beyond the safe integers as a string: an ATR that writes it as a number is declined `atr-malformed`. A pairing whose payment signs no end is paid by `transact` only once its caller raises the ceiling for it. A caller that gives no floor input is declined on every option of that rail. "Every payment is shown before it is signed" holds of `transact`, which asks the approver for each signing; it does not hold of a payment a caller signs itself from `confirm` and `finish`, nor of `agree` and `within`, which take no approver.

16. **Over MCP** (`@integraledger/terms-mcp`). `atr_confirm` and `atr_transact` take `resourceRequest`, the request the 402 answered, in rule 2's form as JSON: over HTTP `{method, target, body, headers?}`, `body` being the body's bytes as padded standard base64 in its canonical form (RFC 4648, section 3.5), as the `atr` argument is read, and `""` for no body; over MCP `{name, arguments?}`. `atr_confirm`'s result holds `summary` alongside `request`: rule 13's summary as JSON, its `atr` written as the result's own `atr` is, `{base64, utf8}`. `createBuyerServer` takes `ceilings`, of rule 8's form, and `floors`, a function the host gives, `(pairing, network) => inputs`, which answers the floor inputs of rule 9 for that pairing on that network (a CAIP-2 id, the account's), or `undefined`, as an object or a promise of one; the server sets them in the `inputs` it passes the gate, and reads no floor input from a tool's `inputs`. A `floors` that throws or rejects gives no floor. Neither is a tool input, so no text the agent reads, the seller's among it, raises a ceiling or names a floor. `atr_transact` also takes `legalContext`, rule 12's input, and returns `ToReturn` as JSON, its bytes written as the result's `atr` is. A tool returns the codes of rule 4 as the gate does.

17. **The vectors** are `vectors/buyer-gate.json`, which both languages run, and every input in them is a published row or a specification's own example. For each code of rule 4 that such an input shows they hold the case that declines and the accepted case it differs from in one member, with the decline expected and the number of times the signer and the approver are called; `option-not-in-atr`, `request-mismatch`, `past-ceiling` and `summary-missing` have no vector, no published row holding an input that shows them, and are held by this profile's rules alone. They also hold the parse's rows that lcp's `core-vectors.json` lacks, each RFC 8259's or RFC 7493's own example, lcp's check-8 rows there being the parse's rows too. Each ATR's SHA-256 is GNU coreutils `sha256sum`, checked with Python's `hashlib`; each source is named in the file's `about`. Nothing in them is the gate's own output.
