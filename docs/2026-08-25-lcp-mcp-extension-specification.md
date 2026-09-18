# The LCP MCP extension — specification v1.1 (DRAFT, not yet declared)

**Class: Specification.** Written 2026-08-25 against the MCP specification revision
[`2026-07-28`](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning#extension-negotiation)
and `@modelcontextprotocol/{server,client,core}@2.0.0`. Companion to
[the ruling](2026-08-25-mcp-extension-ruling.md) that established the mechanism exists and works.

⛔ **DRAFT — nothing declares this yet, and two things must land first.** See §7. Publishing an
identifier fixes a wire identity that a semantic change would force to `-v2`, so this document exists
*before* the declaration rather than after it.

Key words **MUST**, **MUST NOT**, **SHOULD**, **MAY** are to be interpreted as in RFC 2119, as the MCP
extension process requires of an extension specification.

⭐ **Revision v1.1, 2026-09-18 — §4 gains seven `_meta` keys, and nothing else moves.** v1 defined none,
and said so on purpose; this revision defines them before any server emits one, which is the order v1
required. It is **additive**: no field is removed, renamed or retyped, the identifier of §2 does not move
to `…-v2`, and §5's graceful degradation still holds in full — a client that reads none of these keys sees
exactly the behaviour it saw before, because MCP requires unknown `_meta` keys to be ignorable.

---

## 1. Purpose, and the boundary

This extension lets an MCP server declare that it can **verify the legal context bound to a payment
before that payment is made**, so a host can discover the capability without calling a tool.

It is a **declaration only**. It defines no method, no transport, and no obligation on the client.

⛔ **Out of scope, permanently, per the LCP scope line:** how an agent plans, chooses, negotiates or
prices anything. LCP has no opinion on agent operations. This extension says a server can *check a
binding*; it says nothing about what the agent should then do, which is the agent's own policy.

## 2. Identifier

```
com.integraledger/legal-context
```

- The prefix `com.integraledger` is **RULED** and is not a parameter. It is a reverse-DNS vendor prefix
  for a domain we own, which is what the MCP extension process requires of a third party.
  `org.legalcontextprotocol` remains a **reserved, actively refused** namespace and **MUST NOT** be used.
- The name half is `legal-context`. Under the MCP `_meta` key rules a name may carry hyphens between
  alphanumerics, and the mandatory prefix requirement is satisfied by the `/`.
- Servers **MUST** use this exact spelling. It is a **constant**, not a per-deployment parameter: it
  names *which capability is being spoken*, and a per-seller spelling would advertise something no
  counterparty can match.

⚠️ **Do not confuse it with the sealed UCP carrier.** `com.integraledger.legal_context` — **dot form,
underscore** — is the UCP `policies[]` key and means something else on a different protocol. The two
differ by one character and are not interchangeable. Both belong under the wire seal.

## 3. Settings object

```jsonc
{
  "capabilities": {
    "extensions": {
      "com.integraledger/legal-context": {
        "specVersion": "0.1.38"      // OPTIONAL
      }
    }
  }
}
```

| field | type | required | meaning |
|---|---|---|---|
| `specVersion` | `string` | no | The LCP specification revision this server's verification tools conform to. Omitted means unstated, **not** "any". |

⚠️ **The value is whatever `LCP_SPEC_VERSION` says, and it carries a leading `0.`.** An earlier draft of
this example wrote `"1.38"`, which is the number people say out loud; the kernel's constant is `0.1.38`
and that is what goes on the wire. The reference implementation imports it rather than spelling it, so
the emitted value tracks the kernel and this table is describing it rather than deciding it. A reader
comparing a capture against this document should expect the kernel's spelling.

- The settings object **MUST** be a JSON object. An empty object `{}` **MUST** be accepted and means
  *supported, nothing further stated*.
- A client **MUST NOT** treat `specVersion` as a security or correctness input. It is self-reported and
  unverified, exactly as MCP treats `serverInfo`.
- Servers **MUST NOT** add fields not defined here. Adding a **required** field, removing or renaming a
  field, changing a field's type, or altering the meaning of existing behavior is a **breaking change**
  and **MUST** be published under a new identifier (`…-v2`) rather than silently.
- Additional **optional** fields **MAY** be added in a later revision of this document without a new
  identifier.

**Deliberately not in the settings object:** the well-known discovery path, the seller's origin, the
protocol list, and the tool names. The first two are properties of a *seller*, not of the MCP server —
one server verifies many sellers. The last two are already discoverable: protocol coverage is a property
of LCP, and tools are enumerable via `tools/list`. Restating them here would create a second place for a
fact to drift.

## 4. `_meta` keys

**v1 defined none; v1.1 defines the seven below.** The v1 text said so deliberately — *stated explicitly so
that adding one later is a documented revision rather than a surprise on the wire* — and it required that
any future key **MUST** be prefixed `com.integraledger/` and **MUST** be specified here before it is
emitted. This section is that documented revision, and it keeps that rule exactly: a `com.integraledger/`
key that is not written down here **MUST NOT** be emitted by anything claiming this extension.

### 4.1 The seven keys

Six are **result**-side: a server sets them on the result of a `tools/call`. One,
`com.integraledger/intake`, is **request**-side: a client sets it in the call's `_meta`.

| key | direction | value | present |
|---|---|---|---|
| `com.integraledger/atr-hash` | result | the `x-lcp-atr-hash` response header, verbatim | whenever that header arrived |
| `com.integraledger/payment-identifier` | result | the `x-lcp-payment-identifier` response header, verbatim | whenever that header arrived |
| `com.integraledger/receipt` | result | the `x-lcp-receipt` response header, verbatim | only when the buyer has paid — that header is written once, after the transfer |
| `com.integraledger/refusal` | result | the `x-lcp-refusal` response header, verbatim — the base64url refusal log entry | whenever that header arrived |
| `com.integraledger/http-status` | result | the status of that HTTP response, **as a number** | whenever an HTTP response arrived |
| `com.integraledger/relay-stage` | result | `before-payment` or `after-payment` | **only** when no HTTP response arrived at all |
| `com.integraledger/intake` | request | an object whose keys are the seller's declared intake header names and whose values are the strings to send as those headers, verbatim | when the buyer presents one |

### 4.2 The rules that stop the map drifting

⛔ **The four header-derived keys are a mechanical, one-to-one carriage of one named header value, and
nothing else.** One key, one header, fixed by the table above: a reader holding the header name holds the
key and vice versa, so there is no room for the two to disagree. A server **MUST** carry the header's value
**verbatim** as a string, and **MUST NOT** decode it, re-encode it, trim it, case-fold it, pretty-print it,
truncate it, or wrap it in a structure of its own. A value that cannot be carried verbatim **MUST** be
omitted rather than approximated.

⛔ **Absent stays absent.** A key whose header did not arrive **MUST** be omitted. An empty string
**MUST NOT** stand in for a missing header: `""` is a value that decodes to nothing while still looking
like one, which is strictly worse than the key not being there.

- `com.integraledger/http-status` is the one key whose value is not a string. It is the response's status
  code as a number, so a host can tell an origin's 404 from its 200 without parsing prose out of the
  result's text content.
- `com.integraledger/relay-stage` is present **only** when no HTTP response arrived at all — the transport
  failed, or a relay's own timeout elapsed. There is then no status and no header to carry, so a result
  bearing it **MUST NOT** bear any other key of this section. `before-payment` means the buyer's payment had
  not been forwarded and nothing can have been spent; `after-payment` means it had, and the honest reading
  is that the buyer may have paid and been served while the door cannot say so. Those two values are the
  whole set; a third **MUST NOT** be invented without a revision of this document.
- `com.integraledger/intake` carries buyer-presented evidence the seller has declared it will read — and
  only that. Its keys **MUST** be exactly names the seller declares as intake headers; a key that is not
  declared **MUST** cause the call to be refused before any HTTP request is made, rather than dropped
  quietly. It is not a general header tunnel, and nothing else in a call's `_meta` becomes a header.
- Every key above satisfies MCP's published `_meta` key grammar, none sits under the reserved
  `io.modelcontextprotocol/` prefix, and none collides with a key MCP reserves for itself. That is held by
  a drive rather than asserted here: `packages/seller-mcp/test/meta-keys.test.ts` transcribes the published
  grammar and runs it over the keys this document specifies, so a spelling that stopped conforming would
  be red rather than merely wrong.

### 4.3 Why the receipt is a key and not the body

The settlement receipt is a response **header**; the body of a paid response is the resource the buyer
bought. Folding the receipt into the result's content — or answering with the body where the receipt
belongs — hands a buyer the thing they bought in the place the proof they bought it should be, and no proof
at all. It is an easy substitution to make and a hard one to see, because a fixture whose stub body is
shaped like a settlement response performs it convincingly. The reasoning is recorded beside the one place
this repository already carries a receipt, in `packages/seller-mcp/src/mcp.ts`, and it is the reason every
LCP artefact in the table above is a key of its own rather than a field folded into the delivered content.

### 4.4 The two keys this extension does **not** define

`x402/payment` (request) and `x402/payment-response` (result) are **x402's keys, by assertion, and they
stay so.** They are conformant under MCP's grammar — `x402` is a label that starts with a letter and ends
with a digit, and `x402/` has no second label, so the prefix is not reserved — and the reverse-DNS rule is
a **SHOULD** binding whoever chooses the prefix, which here is x402 and not us. A key this extension did
not define is not this extension's to re-spell: emitting `com.integraledger/x402-payment` would be read by
no counterparty and would claim our namespace for somebody else's protocol field.

⭐ The migration rule for them is recorded in `packages/seller-mcp/src/mcp.ts` — if x402 publishes a
reverse-DNS prefix, accept **both** spellings on read for the transition, emit only the published one, and
**refuse when both are present and disagree**. That rule belongs to the key rather than to one server, so
it binds any door that speaks these keys, this repository's included.

### 4.5 The extension identifier is a different construct, and is untouched

`com.integraledger/legal-context` (§2) is the extension **identifier**, declared under
`capabilities.extensions`. An extension is not a `_meta` key: `_meta` keys are what an extension *defines*
for per-request metadata, while the extension itself is declared in capabilities — both spellings exist and
they are not interchangeable, as [the ruling](2026-08-25-mcp-extension-ruling.md) sets out. This revision
adds `_meta` keys and changes nothing about the identifier, the settings object of §3 or the negotiation
of §5.

## 5. Negotiation and fallback

Declared in the `extensions` field of capabilities, per the 2026-07-28 extension-negotiation rules:

- A server implementing this extension **SHOULD** declare it.
- A client that does not recognize the identifier **MUST** ignore it. MCP requires unknown capabilities
  to be ignorable, and nothing here changes message handling.
- **Graceful degradation is total, and this is the point.** A server's tools behave **identically**
  whether or not the client understands the extension. The declaration changes discovery, never
  behavior. This is the "revert to core protocol behavior" branch the MCP specification requires of the
  supporting party; there is no branch in which this extension rejects a request.
- A client **MUST NOT** infer from the declaration that any particular seller's terms are bound. The
  declaration is about the **server's capability**, not about any transaction.

⚠️ **Era note.** `@modelcontextprotocol/server@2.0.0` negotiates wire era **`2025-11-25`** and does not
support `server/discover`, which is where the 2026-07-28 docs show servers advertising extensions. The
`extensions` field is nonetheless carried on capabilities through the legacy `initialize` handshake and
reaches a client verbatim (measured — see the ruling). A declaration made now therefore carries forward
to `server/discover` unchanged when the SDK ships the modern era.

## 6. Conformance

A server conforms when **all** hold:

1. It declares exactly the identifier in §2 under `capabilities.extensions`.
2. Its settings object validates against §3.
3. Its tool behavior is byte-identical with the declaration present and absent.
4. Every `_meta` key it emits under `com.integraledger/` is one of §4's, spelled as §4 spells it and
   carrying the value §4 gives it. ⚠️ v1 of this clause read *"it emits no `_meta` key under
   `com.integraledger/`"*, which was the whole of §4 at the time; §4 now defines seven, and a key
   outside that set is a conformance failure exactly as an undocumented key was then.

⛔ **Conformance is self-assessed and we do not run an index.** There is no adoption directory, no
namespace registry and no conformance listing — consistent with the standing rule that we never run the
index for a thing we publish.

## 7. Status — both blockers worked; the declaration waits on a publish

1. ✅ **The identifier is a constant owned by `@integraledger/lcp-discovery`**, not by this repo, as
   `LCP_MCP_EXTENSION_ID`. That package already owns every identifier of this class —
   `LCP_CAPABILITY_NAME`, `A2A_LCP_EXTENSION_URI` — and `check:wire` derives the seal **by importing
   it**, so a local constant would be a second home for a wire identity *and* invisible to the gate.
2. ✅ **The name half is settled by the house rule**, not by preference. *Follow the vocabulary you are
   writing into* is what gives `LCP_CAPABILITY_NAME` its underscore (UCP spells itself that way); applied
   to MCP the same rule inverts, because MCP's own extensions are `io.modelcontextprotocol/ui`, `/tasks`,
   `/oauth-client-credentials` — slash after the prefix, hyphens in the name.

⚠️ **Still not declared, and the remaining blocker is a version line rather than a decision.** The
constant is staged in `lcp-discovery@0.13.0`, awaiting a 2FA approval that is bound to a person.

⛔⛔ **Why 0.13.0 and not 0.12.3, which is where it first shipped.** Adding a public export is a MINOR.
As a patch it broke the invariant `check:wire` is built on — that every patch inside a line is
API-equivalent — and that gate hard-requires the caret at the minor's zero patch (`^0.12.0`) while
refusing a raised floor. Measured with `0.12.2` resolved, a version squarely inside that range:

```
LCP_MCP_EXTENSION_ID = undefined
used as a capability key -> {"extensions":{"undefined":{}}}
```

A silently wrong wire identity — so the declaration was deliberately **not** shipped against that floor.
Verified afterwards that the invariant had otherwise held: across all nine runtime protocol dependencies,
eight added no exports anywhere in `0.12.x`, and this was the only violation in the line's history.

Once `0.13.0` is live: re-pin this repo to the 0.13 line — which is what makes `check:wire` expect
`^0.13.0`, so the floor and the import finally agree — then declare in one line in `createLcpMcpServer`,
with a test asserting a real client sees it and a control showing nothing when the declaration is removed.

## 8. What this deliberately does not do

It adds no tool, no parser, no protocol row and no public API. It does not widen `PROPOSAL_PARSERS`, and
"universal" continues to mean **reach, not parsers**. The gate does not grow: this is a declaration that
an existing capability exists, which is the whole of it.
