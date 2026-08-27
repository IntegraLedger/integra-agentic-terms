# The LCP MCP extension — specification v1 (DRAFT, not yet declared)

**Class: Specification.** Written 2026-08-25 against the MCP specification revision
[`2026-07-28`](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning#extension-negotiation)
and `@modelcontextprotocol/{server,client,core}@2.0.0`. Companion to
[the ruling](2026-08-25-mcp-extension-ruling.md) that established the mechanism exists and works.

⛔ **DRAFT — nothing declares this yet, and two things must land first.** See §7. Publishing an
identifier fixes a wire identity that a semantic change would force to `-v2`, so this document exists
*before* the declaration rather than after it.

Key words **MUST**, **MUST NOT**, **SHOULD**, **MAY** are to be interpreted as in RFC 2119, as the MCP
extension process requires of an extension specification.

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

**This extension defines no `_meta` keys in v1.** Stated explicitly so that adding one later is a
documented revision rather than a surprise on the wire. Any future key **MUST** be prefixed
`com.integraledger/` and **MUST** be specified here before it is emitted.

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
4. It emits no `_meta` key under `com.integraledger/` (§4).

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
"universal" continues to mean **reach, not parsers**. The guard does not grow: this is a declaration that
an existing capability exists, which is the whole of it.
