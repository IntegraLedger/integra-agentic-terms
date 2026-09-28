/**
 * The buyer gate's operations as MCP tools: `atr_confirm`, `atr_finish`, `atr_check`, `atr_channel_open` and
 * `atr_channel_record_charge`; where the host wires its own signer, `atr_transact` and `atr_channel_within`; and where
 * it wires a signer or an agreement signer, `atr_agree`. Each tool call is one call of the gate; this package adds
 * transport and words, and seals each channel hold it returns so that a hold passed back is used only unchanged.
 */
import { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod";
import {
  agree,
  check,
  confirm,
  finish,
  openChannel,
  recordCharge,
  transact,
  within,
  type Binding,
  type ChannelHold,
  type Chosen,
  type Declined,
  type Fetch,
  type Inputs,
  type Presented,
  type Signature,
  type Signer,
} from "@integraledger/terms";
import { BINDINGS as LCP_BINDINGS, hash, hashEquals, type Json } from "@integraledger/lcp";
import { seal, unseal, type HoldJson } from "./hold.js";
import { VERSION } from "./version.js";

/** Every pairing of the protocol package the gate has a buyer piece for. */
export const BINDINGS: readonly Binding[] = LCP_BINDINGS;

const DESCRIPTIONS = {
  atr_confirm:
    "Before approving a payment: reads the ATR hash the seller advertised, fetches the ATR from the seller's link and " +
    "confirms its SHA-256 matches. On a match returns the ATR's exact bytes, `chosen`, and the signing request that " +
    "carries the hash; sign exactly that request, then call atr_finish with `chosen` and the signature. On a mismatch " +
    "returns an error and nothing to sign. Where the result names an `agreement` URL, the signing request is returned " +
    "only when you pass that agreement's `receipt` for this ATR hash.",
  atr_finish:
    "Rebuilds the payment from `chosen` and the ATR bytes, joins your wallet's signature, and confirms the ATR hash is " +
    "inside what was signed. Send only the `signed` payment it returns.",
  atr_check: "Confirms that a payment carries, inside what was signed, the SHA-256 of the given ATR bytes.",
  atr_transact:
    "Confirms the ATR hash and, only on a match, signs the payment carrying it with this host's signer. Returns the " +
    "payment to send and the ATR's exact bytes to keep.",
  atr_agree:
    "Pays the agreement URL that atr_confirm named, with this host's signer, for the ATR you confirmed: the agreement " +
    "payment carries the ATR hash. Returns the agreement's receipt once it is recorded; pass it to atr_confirm.",
  atr_channel_open:
    "Keeps a channel you opened: takes the signed opening payment and the ATR bytes it was confirmed against, and " +
    "returns the channel `hold` to keep and pass to the other channel tools. The hold is opaque: pass it back exactly " +
    "as returned.",
  atr_channel_within:
    "Signs one later payment in a held channel with this host's signer, only when the seller's document advertises " +
    "the held ATR hash. Takes the latest `hold` exactly as returned; a changed hold is declined. Returns the payment " +
    "to send and the updated `hold`.",
  atr_channel_record_charge:
    "Records the seller's cumulative charge in a held channel, no lower than the last recorded and no higher than " +
    "what was signed. Takes the latest `hold` exactly as returned; a changed hold is declined. Returns the updated " +
    "`hold`.",
} as const;

type Result = {
  content: { type: "text"; text: string }[];
  structuredContent: { [k: string]: unknown };
  isError?: boolean;
};

/** A tool result whose text block is the JSON of its structured content. */
function result(structuredContent: { [k: string]: unknown }, isError = false): Result {
  const r: Result = { content: [{ type: "text", text: JSON.stringify(structuredContent) }], structuredContent };
  return isError ? { ...r, isError: true } : r;
}

/** A decline, with what the signer moved, where it moved the payment: the signed payment, the ATR's bytes and hash. */
const declinedResult = (d: Declined): Result =>
  result(
    {
      decline: { code: d.decline.code, detail: d.decline.detail },
      ...(d.moved !== undefined
        ? { moved: { signed: jsonOf(d.moved.signed), atr: atrOf(d.moved.bytes), atrHash: d.moved.h } }
        : {}),
    },
    true,
  );

/** A value as JSON: every bigint as a decimal string and every byte string as `0x` hex. */
function jsonOf(v: unknown): Json {
  if (typeof v === "bigint") return v.toString();
  if (v instanceof Uint8Array) {
    let s = "0x";
    for (const b of v) s += (b < 16 ? "0" : "") + b.toString(16);
    return s;
  }
  if (Array.isArray(v)) return v.map(jsonOf);
  if (typeof v === "object" && v !== null) {
    const out: { [k: string]: Json } = {};
    for (const [k, x] of Object.entries(v)) if (x !== undefined && typeof x !== "function") out[k] = jsonOf(x);
    return out;
  }
  return v as Json;
}

/** The exact bytes as standard base64, and as UTF-8 text, or null where they are not valid UTF-8. */
function atrOf(bytes: Uint8Array): { base64: string; utf8: string | null } {
  let utf8: string | null;
  try {
    utf8 = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    utf8 = null;
  }
  return { base64: Buffer.from(bytes).toString("base64"), utf8 };
}

/** The decline for a hold whose `mac` does not verify: a changed hold, or one another server process returned. */
const holdUnverified = (): Result =>
  result(
    {
      decline: {
        code: "hold-unverified",
        detail: "The hold is not one this server process returned, unchanged. Pass back the latest hold exactly as returned.",
      },
    },
    true,
  );

/** The bytes of a standard base64 string. */
const bytesOf = (base64: string): Uint8Array => new Uint8Array(Buffer.from(base64, "base64"));

const JSON_VALUE: z.ZodType<Json> = z.json() as z.ZodType<Json>;

/** The agreement receipt for `h`: `{atrHash, agreed: true, network, transaction}` naming this ATR hash. */
function isReceiptFor(receipt: unknown, h: string): boolean {
  if (typeof receipt !== "object" || receipt === null || Array.isArray(receipt)) return false;
  const { atrHash, agreed, network, transaction } = receipt as Record<string, unknown>;
  return (
    typeof atrHash === "string" &&
    hashEquals(atrHash, h) &&
    agreed === true &&
    typeof network === "string" &&
    typeof transaction === "string"
  );
}

/** The payment and, where `finish` or `transact` returned one, the landed receipt beside it. */
function signedOf(out: { signed: Presented | null; landed?: unknown }): { signed: Json; landed?: Json } {
  return out.landed === undefined ? { signed: jsonOf(out.signed) } : { signed: jsonOf(out.signed), landed: jsonOf(out.landed) };
}

export function createBuyerServer(options: { fetch: Fetch; signer?: Signer; agreementSigner?: Signer }): McpServer {
  const byId = new Map(BINDINGS.map((b) => [b.id as string, b]));
  const ids = [...byId.keys()] as [string, ...string[]];
  const pairing = z.enum(ids);
  const atr = z.base64();
  const inputs = z.record(z.string(), JSON_VALUE).optional();
  const bindingOf = (id: string): Binding => byId.get(id)!;
  const { fetch, signer, agreementSigner } = options;
  const payer = agreementSigner ?? signer;

  const server = new McpServer({ name: "integraledger-terms", version: VERSION }, { capabilities: { tools: {} } });

  server.registerTool(
    "atr_confirm",
    {
      description: DESCRIPTIONS.atr_confirm,
      inputSchema: z.object({ pairing, document: JSON_VALUE, account: z.string(), inputs, receipt: JSON_VALUE.optional() }),
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async (a) => {
      const out = await confirm(a.document, bindingOf(a.pairing), a.account, fetch, (a.inputs ?? {}) as Inputs);
      if ("decline" in out) return declinedResult(out);
      const confirmed = { atrHash: out.h, atr: atrOf(out.bytes), chosen: out.chosen };
      if (out.agreement === undefined) return result({ ...confirmed, request: jsonOf(out.request) });
      if (a.receipt === undefined) return result({ ...confirmed, agreement: out.agreement });
      if (!isReceiptFor(a.receipt, out.h)) {
        return declinedResult({
          decline: { code: "agreement-failed", detail: "The agreement receipt is not a recorded agreement for this ATR hash." },
        });
      }
      return result({ ...confirmed, request: jsonOf(out.request), agreement: out.agreement });
    },
  );

  server.registerTool(
    "atr_finish",
    {
      description: DESCRIPTIONS.atr_finish,
      inputSchema: z.object({ pairing, atr, chosen: z.record(z.string(), JSON_VALUE), signature: JSON_VALUE }),
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async (a) => {
      const out = await finish(bytesOf(a.atr), a.chosen as unknown as Chosen, a.signature as Signature, bindingOf(a.pairing));
      if ("decline" in out) return declinedResult(out);
      if ("next" in out) return result({ atrHash: out.h, next: jsonOf(out.next) });
      return result({ atrHash: out.h, ...signedOf(out) });
    },
  );

  server.registerTool(
    "atr_check",
    {
      description: DESCRIPTIONS.atr_check,
      inputSchema: z.object({ pairing, atr, presented: JSON_VALUE }),
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async (a) => {
      const out = await check(bytesOf(a.atr), a.presented, bindingOf(a.pairing));
      if ("decline" in out) return declinedResult(out);
      return result({ atrHash: out.h });
    },
  );

  if (signer !== undefined) {
    server.registerTool(
      "atr_transact",
      {
        description: DESCRIPTIONS.atr_transact,
        inputSchema: z.object({ pairing, document: JSON_VALUE, inputs }),
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
      },
      async (a) => {
        const out = await transact(a.document, bindingOf(a.pairing), signer, fetch, {
          inputs: (a.inputs ?? {}) as Inputs,
          agreementSigner,
        });
        if ("decline" in out) return declinedResult(out);
        const agreement = out.agreement === undefined ? {} : { agreement: jsonOf(out.agreement) };
        return result({ atrHash: out.h, atr: atrOf(out.bytes), ...signedOf(out), ...agreement });
      },
    );
  }

  if (payer !== undefined) {
    server.registerTool(
      "atr_agree",
      {
        description: DESCRIPTIONS.atr_agree,
        inputSchema: z.object({ atr, agreement: z.string(), inputs }),
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
      },
      async (a) => {
        const bytes = bytesOf(a.atr);
        const out = await agree(await hash(bytes), a.agreement, payer, fetch, { bytes, inputs: (a.inputs ?? {}) as Inputs });
        if ("decline" in out) return declinedResult(out);
        return result({ atrHash: out.receipt.atrHash, receipt: jsonOf(out.receipt) });
      },
    );
  }

  const hold = z.record(z.string(), JSON_VALUE);
  server.registerTool(
    "atr_channel_open",
    {
      description: DESCRIPTIONS.atr_channel_open,
      inputSchema: z.object({ pairing, atr, signed: JSON_VALUE }),
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async (a) => {
      const out = await openChannel(bytesOf(a.atr), a.signed as Presented, bindingOf(a.pairing));
      if ("decline" in out) return declinedResult(out);
      return result({ atrHash: out.h, hold: await seal(jsonOf(out) as HoldJson) });
    },
  );

  server.registerTool(
    "atr_channel_record_charge",
    {
      description: DESCRIPTIONS.atr_channel_record_charge,
      inputSchema: z.object({ hold, charged: z.string() }),
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async (a) => {
      const held = await unseal(a.hold);
      if (held === undefined) return holdUnverified();
      const out = recordCharge(held as unknown as ChannelHold, a.charged);
      if ("decline" in out) return declinedResult(out);
      return result({ atrHash: out.h, hold: await seal(jsonOf(out) as HoldJson) });
    },
  );

  if (signer !== undefined) {
    server.registerTool(
      "atr_channel_within",
      {
        description: DESCRIPTIONS.atr_channel_within,
        inputSchema: z.object({
          pairing,
          hold,
          document: JSON_VALUE,
          refund: z.object({ amount: z.string().optional() }).optional(),
          inputs,
        }),
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
      },
      async (a) => {
        const held = await unseal(a.hold);
        if (held === undefined) return holdUnverified();
        const refund = a.refund === undefined ? undefined : a.refund.amount === undefined ? {} : { amount: a.refund.amount };
        const out = await within(
          a.document,
          held as unknown as ChannelHold,
          bindingOf(a.pairing),
          signer,
          refund,
          (a.inputs ?? {}) as Inputs,
        );
        if ("decline" in out) return declinedResult(out);
        return result({ atrHash: out.hold.h, signed: jsonOf(out.signed), hold: await seal(jsonOf(out.hold) as HoldJson) });
      },
    );
  }
  return server;
}
