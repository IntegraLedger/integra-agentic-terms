/**
 * The buyer gate's operations as MCP tools: `atr_confirm`, `atr_finish`, `atr_check`, `atr_channel_open` and
 * `atr_channel_record_charge`; where the host wires its own signer, `atr_transact` and `atr_channel_within`; and where
 * it wires a signer or an agreement signer, `atr_agree`. Each tool call is one call of the gate; this package adds
 * transport and words, and seals each `chosen`, channel hold and channel opening it returns. A channel hold or opening
 * passed back is used only unchanged, and so is a `chosen` passed to `atr_agree`, or to `atr_finish` for a pairing
 * with a channel.
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
  type AgreementPayment,
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
import { BINDINGS as LCP_BINDINGS, hashEquals, type Json } from "@integraledger/lcp";
import { fromBase64, toBase64 } from "@integraledger/lcp/core";
import { macOf, seal, unseal, verifies, type HoldJson } from "./hold.js";
import { VERSION } from "./version.js";

/** Every pairing of the protocol package the gate has a buyer piece for. */
export const BINDINGS: readonly Binding[] = LCP_BINDINGS;

const DESCRIPTIONS = {
  atr_confirm:
    "Before approving a payment: reads the ATR hash the seller advertised, fetches the ATR from the seller's link and " +
    "confirms its SHA-256 matches. On a match returns the ATR's exact bytes, `chosen`, and the signing request built " +
    "with that hash; sign exactly that request, then call atr_finish with `chosen` and the signature. On a mismatch " +
    "returns an error and nothing to sign. `chosen` is opaque: pass it back exactly as returned, `mac` included. Where " +
    "`chosen.agreement` names an agreement URL, the signing request is returned only when you pass that agreement's " +
    "`receipt` for this ATR hash.",
  atr_finish:
    "Rebuilds the payment from `chosen` and the ATR bytes and joins your wallet's signature. Returns `signed` only " +
    "when the pairing reads the ATR hash from the completed payment, or, where the proof is the agreement payment, " +
    "without that reading. For a pairing with a channel, pass `chosen` exactly as atr_confirm returned it, `mac` " +
    "included: a changed `chosen` is declined. Send only the `signed` payment it returns.",
  atr_check:
    "Confirms that the ATR hash the pairing reads from a payment is the SHA-256 of the given ATR bytes, with the " +
    "`landed` receipt returned beside the payment, exactly as returned, where there is one. The caller passes as " +
    "`landed` only the receipt its own reader read for the payment, as `atr_finish` or `atr_transact` returned it, " +
    "never a value another party sent. A `landed` of null is no receipt. A payment from which the pairing reads no " +
    "ATR hash is declined.",
  atr_transact:
    "Confirms the ATR hash and, only on a match, signs the payment carrying it with this host's signer. Returns the " +
    "payment to send and the ATR's exact bytes to keep. Where the pairing needs an agreement payment first, returns it " +
    "as `approve` and signs nothing: its `option` holds the amount, asset, payee (`payTo`) and network it pays. To " +
    "approve it, call atr_transact again with the same arguments and `approved` set to `approve`, unchanged.",
  atr_agree:
    "The agreement payment for the agreement URL in the `chosen` that atr_confirm returned, for the ATR you confirmed; " +
    "pass `chosen` exactly as returned, since a changed `chosen` is declined. " +
    "Without `approved`, returns the payment as `approve` and signs nothing: its `option` holds the amount, asset, " +
    "payee (`payTo`) and network it pays, and it carries the ATR hash. To approve it, call atr_agree again with " +
    "`approved` set to `approve`, unchanged: this host's signer then pays it. Returns the agreement's receipt once it " +
    "is recorded; pass it to atr_confirm.",
  atr_channel_open:
    "Keeps a channel you opened: takes the signed opening payment, the `landed` receipt where one was returned beside " +
    "it, and the `mac` returned beside it, all exactly as returned, and the ATR bytes it was confirmed against; " +
    "returns the channel `hold` to keep and pass to the other channel tools. The caller passes as `landed` only the " +
    "receipt its own reader read for the opening, as `atr_finish` or `atr_transact` returned it, never a value " +
    "another party sent. The hold is opaque: pass it back exactly as returned.",
  atr_channel_within:
    "Signs one later payment in a held channel with this host's signer. The ATR, its hash and the channel come from " +
    "the `hold`, and the amount from the seller's new document, with no limit applied. On an x402 channel the " +
    "document must advertise the held ATR hash, and the payment must name the held channel. On an MPP session a " +
    "challenge that names another channel or another ATR hash is declined, and one with no legal context is signed " +
    "under the held ATR hash. Takes the latest `hold` exactly as returned; a changed hold is declined. Returns the " +
    "payment to send and the updated `hold`. With `refund`, signs a refund in place of a voucher. A Solana refund is " +
    "taken again, with the payer-signed request_close built from `inputs`' `recentBlockhash`, when " +
    "`refund.paymentResponse`, the seller's decoded `PAYMENT-RESPONSE`, has the `errorReason` " +
    "`invalid_batch_settlement_svm_receiver_binding_unavailable`, read first, or else the document's `error` is " +
    "that code.",
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

/**
 * The exact bytes as padded standard base64 in its canonical form, written by the protocol package, and as UTF-8 text,
 * or null where they are not valid UTF-8.
 */
function atrOf(bytes: Uint8Array): { base64: string; utf8: string | null } {
  let utf8: string | null;
  try {
    utf8 = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    utf8 = null;
  }
  return { base64: toBase64(bytes), utf8 };
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

/** The decline for an opening whose `mac` does not verify: a changed opening, or one another server process returned. */
const openingUnverified = (): Result =>
  result(
    {
      decline: {
        code: "opening-unverified",
        detail:
          "The opening is not one this server process returned, unchanged. Pass the signed opening and its mac exactly as returned.",
      },
    },
    true,
  );

/** The decline for a `chosen` whose `mac` does not verify: a changed `chosen`, or one another server process returned. */
const chosenUnverified = (): Result =>
  result(
    {
      decline: {
        code: "chosen-unverified",
        detail:
          "The chosen payment is not one this server process returned, unchanged. Pass chosen exactly as atr_confirm returned it.",
      },
    },
    true,
  );

/** `chosen` with its `mac`: this process's HMAC-SHA-256 of every other member. */
async function sealChosen(chosen: Chosen): Promise<HoldJson> {
  const members = jsonOf(chosen) as HoldJson;
  return { ...members, mac: await macOf("chosen", members) };
}

/** `chosen`'s members without `mac` when `mac` is this process's HMAC-SHA-256 of them, else undefined. */
async function unsealChosen(chosen: HoldJson): Promise<HoldJson | undefined> {
  const { mac, ...members } = chosen;
  return (await verifies("chosen", members, mac)) ? members : undefined;
}

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

/** Whether the pairing has a channel: its opening is held, and later payments are signed in it. */
function hasChannel(binding: Binding): boolean {
  const channel = (binding as unknown as { channel?: unknown }).channel;
  return typeof channel === "object" && channel !== null;
}

/**
 * The payment and, where `finish` or `transact` returned one, the landed receipt beside it; for a pairing with a
 * channel, the `mac` of the pairing, the payment and that receipt, which `atr_channel_open` takes with them.
 */
async function signedOf(
  out: { signed: Presented | null; landed?: unknown },
  binding: Binding,
): Promise<{ signed: Json; landed?: Json; mac?: string }> {
  const signed = jsonOf(out.signed);
  const landed = out.landed === undefined ? {} : { landed: jsonOf(out.landed) };
  if (!hasChannel(binding) || out.signed === null) return { signed, ...landed };
  return { signed, ...landed, mac: await macOf("opening", { pairing: binding.id, signed, ...landed }) };
}

export function createBuyerServer(options: { fetch: Fetch; signer?: Signer; agreementSigner?: Signer }): McpServer {
  const byId = new Map(BINDINGS.map((b) => [b.id as string, b]));
  const ids = [...byId.keys()] as [string, ...string[]];
  const pairing = z.enum(ids);
  /**
   * An `atr` argument, read as the ATR's bytes: padded standard base64 in its canonical form (RFC 4648 §3.5), through
   * the protocol package's reader. Any other value fails the tool's input schema, as any malformed argument does, so
   * the tool fetches and signs nothing for it.
   */
  const atr = z.base64().transform((base64, ctx): Uint8Array => {
    const bytes = fromBase64(base64);
    if (bytes !== null) return bytes;
    ctx.addIssue({ code: "custom", input: base64, message: "Not padded standard base64 in its canonical form (RFC 4648 §3.5)" });
    return z.NEVER;
  });
  const inputs = z.record(z.string(), JSON_VALUE).optional();
  const approved = z.record(z.string(), JSON_VALUE).optional();
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
      const confirmed = { atrHash: out.h, atr: atrOf(out.bytes), chosen: await sealChosen(out.chosen) };
      if (out.chosen.agreement === undefined) return result({ ...confirmed, request: jsonOf(out.request) });
      if (a.receipt === undefined) return result(confirmed);
      if (!isReceiptFor(a.receipt, out.h)) {
        return declinedResult({
          decline: { code: "agreement-failed", detail: "The agreement receipt is not a recorded agreement for this ATR hash." },
        });
      }
      return result({ ...confirmed, request: jsonOf(out.request) });
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
      const binding = bindingOf(a.pairing);
      const { mac: _mac, ...members } = a.chosen;
      const chosen = hasChannel(binding) ? await unsealChosen(a.chosen) : members;
      if (chosen === undefined) return chosenUnverified();
      const out = await finish(a.atr, chosen as unknown as Chosen, a.signature as Signature, binding);
      if ("decline" in out) return declinedResult(out);
      if ("next" in out) return result({ atrHash: out.h, next: jsonOf(out.next) });
      return result({ atrHash: out.h, ...(await signedOf(out, binding)) });
    },
  );

  server.registerTool(
    "atr_check",
    {
      description: DESCRIPTIONS.atr_check,
      inputSchema: z.object({ pairing, atr, presented: JSON_VALUE, landed: JSON_VALUE.optional() }),
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async (a) => {
      const out = await check(a.atr, a.presented, bindingOf(a.pairing), a.landed);
      if ("decline" in out) return declinedResult(out);
      return result({ atrHash: out.h });
    },
  );

  if (signer !== undefined) {
    server.registerTool(
      "atr_transact",
      {
        description: DESCRIPTIONS.atr_transact,
        inputSchema: z.object({ pairing, document: JSON_VALUE, inputs, approved }),
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
      },
      async (a, ctx) => {
        const out = await transact(a.document, bindingOf(a.pairing), signer, fetch, {
          inputs: (a.inputs ?? {}) as Inputs,
          agreementSigner,
          approved: a.approved as AgreementPayment | undefined,
          signal: ctx.mcpReq.signal,
        });
        if ("decline" in out) return declinedResult(out);
        if ("approve" in out) return result({ atrHash: out.h, atr: atrOf(out.bytes), approve: jsonOf(out.approve) });
        const agreement = out.agreement === undefined ? {} : { agreement: jsonOf(out.agreement) };
        return result({ atrHash: out.h, atr: atrOf(out.bytes), ...(await signedOf(out, bindingOf(a.pairing))), ...agreement });
      },
    );
  }

  if (payer !== undefined) {
    server.registerTool(
      "atr_agree",
      {
        description: DESCRIPTIONS.atr_agree,
        inputSchema: z.object({ atr, chosen: z.record(z.string(), JSON_VALUE), approved, inputs }),
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
      },
      async (a, ctx) => {
        const chosen = await unsealChosen(a.chosen);
        if (chosen === undefined) return chosenUnverified();
        const url = chosen["agreement"];
        if (typeof url !== "string") {
          return declinedResult({
            decline: { code: "offer-unreadable", detail: "The chosen payment names no agreement URL." },
          });
        }
        const out = await agree(a.atr, url, payer, fetch, {
          approved: a.approved as AgreementPayment | undefined,
          inputs: (a.inputs ?? {}) as Inputs,
          signal: ctx.mcpReq.signal,
        });
        if ("decline" in out) return declinedResult(out);
        if ("approve" in out) return result({ atrHash: out.h, approve: jsonOf(out.approve) });
        return result({ atrHash: out.receipt.atrHash, receipt: jsonOf(out.receipt) });
      },
    );
  }

  const hold = z.record(z.string(), JSON_VALUE);
  server.registerTool(
    "atr_channel_open",
    {
      description: DESCRIPTIONS.atr_channel_open,
      inputSchema: z.object({ pairing, atr, signed: JSON_VALUE, landed: JSON_VALUE.optional(), mac: z.string() }),
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async (a) => {
      const landed = a.landed === undefined ? {} : { landed: a.landed };
      if (!(await verifies("opening", { pairing: a.pairing, signed: a.signed, ...landed }, a.mac))) return openingUnverified();
      const out = await openChannel(a.atr, a.signed as Presented, bindingOf(a.pairing), a.landed);
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
          refund: z.object({ amount: z.string().optional(), paymentResponse: JSON_VALUE.optional() }).optional(),
          inputs,
        }),
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
      },
      async (a) => {
        const held = await unseal(a.hold);
        if (held === undefined) return holdUnverified();
        const refund =
          a.refund === undefined
            ? undefined
            : {
                ...(a.refund.amount === undefined ? {} : { amount: a.refund.amount }),
                ...(a.refund.paymentResponse === undefined ? {} : { paymentResponse: a.refund.paymentResponse }),
              };
        const out = await within(
          a.document,
          held as unknown as ChannelHold,
          bindingOf(a.pairing),
          signer,
          refund as Parameters<typeof within>[4],
          (a.inputs ?? {}) as Inputs,
        );
        if ("decline" in out) return declinedResult(out);
        return result({ atrHash: out.hold.h, signed: jsonOf(out.signed), hold: await seal(jsonOf(out.hold) as HoldJson) });
      },
    );
  }
  return server;
}
