# The MCP extension — measured against the shipped SDK, and ruled

**Class: Ruling.** Written 2026-08-25 against `integra-agentic-terms@30bfe69` (clean, pushed) with
`@modelcontextprotocol/{server,client,core}@2.0.0` installed from the `catalog:` pin.

**Ruling in one line: it is a capability declaration, not a `_meta` key — and it is NOT YET SHIPPABLE,
blocked on a document we have not written, not on code.**

The mechanism is real, spec-sanctioned, and works today; that part of the prior finding is overturned.
What is missing is the published extension specification that gives the identifier a meaning, and an
identifier without one is a wire identity that says nothing and cannot easily be taken back.

---

## 1. What the 2026-07-28 specification actually says

Read 2026-08-25 at [`basic/versioning#extension-negotiation`][versioning] and
[`docs/extensions/overview`][overview]. The normative sentence:

> Extensions are advertised in the `extensions` field of capabilities, which is a map of extension
> identifiers to per-extension settings objects. Extension identifiers **MUST** follow the
> [`_meta` key naming rules][meta], with a mandatory prefix.

So the declaration point is **`capabilities.extensions["<vendor-prefix>/<name>"]`**, and the settings
value is an object — `{}` meaning "supported, no settings".

Three consequences, each of which decides something below.

- **An extension is not a `_meta` key.** `_meta` keys are what an extension *defines* for per-request
  metadata; the extension itself is declared in capabilities. Both spellings exist and they are not
  interchangeable.
- **A third-party extension needs no SEP.** The SEP/working-group lifecycle in `docs/extensions/overview`
  governs *official* `io.modelcontextprotocol/` extensions. For everyone else the spec says only: *"use a
  reversed domain name you own as the vendor prefix."* Nothing to register, no one to ask.
- **But the extension must document its settings schema.** *"Each extension specifies the schema of its
  settings object"*, and `_meta` keys an extension defines *"are specified in the extension's
  documentation."* This is the sentence that blocks us — see §5.

`com.integraledger/legal-context` is a **valid** identifier: labels start with a letter and end
alphanumeric; the second label is `integraledger`, so it is not caught by the reservation on
`modelcontextprotocol`/`mcp`; the name half may carry hyphens between alphanumerics.

## 2. ⛔⛔ The prior finding is overturned — the SDK ships the field

The brief and the design doc both record *"the SDK has **no Extensions API**"*, with the only literal
"Extension" being an English phrase in a private docblock. **That is wrong, and the error is instructive:
the search was for an Extensions *API* — a class, a `registerExtension()` — and the spec's mechanism is
not an API. It is a declarative field, and the field is there.**

Both capability schemas carry it, verbatim from the installed runtime:

```js
// @modelcontextprotocol/core@2.0.0 — dist/auth-CUe6YdwF.mjs
const ClientCapabilitiesSchema = z.object({ …, extensions: z.record(z.string(), JSONObjectSchema).optional() });
const ServerCapabilitiesSchema = z.object({ …, extensions: z.record(z.string(), JSONObjectSchema).optional() });
```

`ServerOptions.capabilities` is typed `ServerCapabilities`, so `new McpServer(info, { capabilities })`
accepts it. **Measured end-to-end** — real `McpServer`, real `Client`, real `InMemoryTransport` — the
declaration reaches the client verbatim, and the control with the declaration removed shows nothing:

```
SUBJECT  client-visible: {"tools":{"listChanged":true},"extensions":{"com.integraledger/legal-context":{"specVersion":"1.38"}}}
CONTROL  declaration removed → {"tools":{"listChanged":true}}          (assertion can fail)
```

Registering tools and declaring an extension compose: `tools` is still derived from the registrations.

## 3. ⛔⛔ The shape the prior research validated transmits NOTHING

The recorded measurement was that a reverse-DNS key **on `ServerCapabilities` itself** is accepted:
`{"tools":{},"com.integraledger/legal_context":{…}}` → ACCEPTED, with `{"tools":"not-an-object"}` and
`{"tools":{"listChanged":"yes"}}` → REJECTED as controls.

Every one of those results reproduces. **They are also the repo's own trap class.** `ServerCapabilitiesSchema`
is `z.object`, not `z.looseObject`, and Zod strips unknown keys rather than rejecting them. The parse
succeeds and the key is **silently discarded**:

```
input:  {"tools":{},"com.integraledger/legal_context":{"specVersion":"1.38"}}
parsed: {"tools":{}}                       >>> key SURVIVED? NO — SILENTLY STRIPPED
e2e:    client-visible capabilities        {"tools":{"listChanged":true}}
```

**Had we shipped on that finding, the server would have advertised nothing, and every probe would have
said ACCEPTED.** The controls were real controls — malformed input really was rejected — which is exactly
why the green was persuasive. What no control asked was whether the accepted key *came out the other side*.
The failing controls proved the schema was being reached; they could not prove the key was being kept.

⭐ **The generalization worth keeping: against a permissive-by-default validator, `parse()` succeeding is
not evidence a field is carried. Assert the parsed OUTPUT, and better, assert what the counterparty sees.**

## 4. Era — `server/discover` does not exist here

The brief records the SDK as *"carries revision `2026-07-28`"*. **True of its docblocks; false of its
wire.** The 2026-07-28 strings in the SDK are documentation links, plus 21 `@deprecated` notices marking
what that revision retires. Those notices cover **three** client-feature surfaces, not one — worth knowing
independently of this ruling, because two of them are load-bearing elsewhere in MCP:

| Retired in 2026-07-28 | Migrate to |
|---|---|
| logging (`logging/setLevel`, log notifications) | stderr logging (STDIO servers) or OpenTelemetry |
| sampling (`sampling/createMessage`, model preferences) | calling LLM provider APIs directly |
| roots (`roots/list`, root notifications) | passing paths via tool parameters, resource URIs, or configuration |

Each *"remains in the specification for at least twelve months."* None of this touches extensions; it is
recorded because a reader who trusts "the SDK carries 2026-07-28" will also assume these still work.

The negotiated version tops out one revision earlier:

```
LATEST_PROTOCOL_VERSION            2025-11-25
DEFAULT_NEGOTIATED_PROTOCOL_VERSION 2025-03-26
SUPPORTED_PROTOCOL_VERSIONS        ["2025-11-25","2025-06-18","2025-03-26","2024-11-05","2024-10-07"]
```

`2026-07-28` is **absent**. In the spec's own terminology that makes this SDK **legacy-era** — an
`initialize` handshake, not per-request metadata. The SDK says so itself when asked for the modern
advertisement point:

```
server/discover FAILED: METHOD_NOT_SUPPORTED_BY_PROTOCOL_VERSION
  Method 'server/discover' is not supported by the negotiated protocol version (wire era 2025-11-25)
```

This matters because `docs/extensions/overview` shows servers advertising extensions **in the
`server/discover` response** — a method we cannot answer. What we *can* do is carry `extensions` in the
legacy `initialize` capabilities, which the SDK back-ports and which §2 measured working. Same structure,
so a declaration made today carries forward to `server/discover` unchanged when the SDK ships modern era.

## 5. Why it is not yet shippable

Not "it doesn't work" — it works. Three reasons, in order of weight.

1. **There is no LCP MCP extension specification to point at.** The spec requires an extension to define
   its settings-object schema and any `_meta` keys in its own documentation. We would be publishing
   `com.integraledger/legal-context` with nothing behind it. A counterparty reading it can discover *that*
   we claim it and never *what* it means, and `{}` as a settings object would assert support for a thing
   that does not exist. This repo does not overstate on the wire.
2. **It is a new wire identity, and those are hard to take back.** The design doc's §7 is explicit: an
   extension identifier *"is a wire identity a counterparty must know, so it is very hard to change after
   publication and belongs under the seal once chosen."* Publishing before the meaning is fixed inverts
   that order. Per `docs/extensions/overview`, a breaking change to an extension's semantics forces a new
   identifier (`…-v2`) — the cost of getting this wrong is paid in permanent vocabulary.
3. **The reach on offer today is partial.** The advertisement point hosts will read — `server/discover` —
   is unavailable in this era. Declaring now buys the legacy handshake only, at the price of fixing an
   identity permanently. The trade improves on its own when the SDK ships 2026-07-28; nothing is lost by
   waiting, and the identifier is better for having a document.

⚠️ **A naming collision to settle before anything is published.** The seal already holds
`LCP_CAPABILITY_NAME: "com.integraledger.legal_context"` — **dot form, underscore** — and that is the
**UCP** `policies[]` carrier, not an MCP identifier (its one use is a UCP fixture in
`proposal-universal.test.ts`). MCP mandates `{vendor-prefix}/{extension-name}`, so the MCP identity would
be `com.integraledger/legal-context` — **slash form, hyphen**. Two wire identities differing by one
character, on two protocols, meaning different things. Whatever is chosen, both belong under the seal
with the distinction written down.

## 6. What this does NOT do — the fence holds

Declaring an extension adds no tool, no parser, no protocol row, and no public surface; it is one field in
a constructor. It does not touch `PROPOSAL_PARSERS` and does not grow the gate. Graceful degradation is
automatic: our tools behave identically whether or not a client understands the extension, which is the
"revert to core protocol behavior" branch the spec requires. **The blocker is a document, not a feature.**

## 7. Recommended next step — cheap, and not taken here

Write the LCP MCP extension specification: identifier, settings-object schema, any `_meta` keys, and the
fallback behavior. It is a short document, needs nobody's permission, and once it exists the declaration
is a one-line constructor change plus a seal entry. When it is written, the settings object should
plausibly carry the LCP spec version it conforms to and the well-known path — but that is the document's
decision to make, not this ruling's.

## 8. Re-measuring this — verbatim

```bash
cd integra-july-2026/integra-agentic-terms
export PATH="$HOME/.nvm/versions/node/v24.18.0/bin:$PATH"
CORE="$PWD/node_modules/.pnpm/@modelcontextprotocol+core@2.0.0/node_modules/@modelcontextprotocol/core"

# era — is 2026-07-28 negotiable?
node -e "import('file://$CORE/dist/internal.mjs').then(m=>console.log(m.LATEST_PROTOCOL_VERSION, JSON.stringify(m.SUPPORTED_PROTOCOL_VERSIONS)))"

# does the field exist on BOTH capability schemas, and is the schema still strip-on-unknown?
# Chunk filenames are bundler-hashed and change on every SDK bump, so match on content, not path.
# `--include='*.mjs'` matters: without it the sourcemaps match and this prints ~258KB.
grep -rhA 12 --include='*.mjs' 'const \(Client\|Server\)CapabilitiesSchema = ' "$CORE/dist" \
  | grep -E 'CapabilitiesSchema = |extensions: z.record'
```

Expected today — four lines, and the `z.object` on each is what §3 turns on (a change to
`z.looseObject` in a later SDK would make the stripped shape start transmitting):

```
const ClientCapabilitiesSchema = z.object({
	extensions: z.record(z.string(), JSONObjectSchema).optional()
const ServerCapabilitiesSchema = z.object({
	extensions: z.record(z.string(), JSONObjectSchema).optional()
```

The two probe scripts behind §2 and §3 assert the parsed **output** and the **client-visible**
capabilities, each with a control that must show nothing. They are deliberately not committed: they
measure a dependency we do not yet depend on, and a gate over unshipped behavior is a gate that cannot
go red for a reason we care about.

[versioning]: https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning#extension-negotiation
[overview]: https://modelcontextprotocol.io/docs/extensions/overview
[meta]: https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta
