// The summaries of the Solana, XRP Ledger, Algorand, Stacks and Hedera requests (terms' profile buyer-gate.md, rule
// 13), each over a request the protocol package's vectors hold, as a stock library, a hand-written wire or the
// pairing's build on the file's own inputs gives it, and each expected member read from the same file: the row is
// cited beside it. A request whose bytes name no network is shown with the signer's account's, the network of the
// file's option or challenge.
import { describe, expect, it } from "vitest";
import { decodeBlob } from "@integraledger/lcp/xrpl";
import { decodeSvmTx } from "@integraledger/lcp/svm";
import { BINDINGS } from "@integraledger/lcp";
import type { Binding, SigningRequest } from "../src/index.js";
import { SUMMARIES, summaryOf, type Shown } from "../src/summary.js";
import { algorandTransfer } from "../src/summary/algorand-txn.js";
import { hederaExecutor, hederaTransfer } from "../src/summary/hedera-body.js";
import { solanaSessionOpen, solanaTransfer, solanaUptoOpen } from "../src/summary/solana-message.js";
import { stacksTransfer } from "../src/summary/stacks-contract-call.js";
import { xrplPayment, xrplSessionOpen } from "../src/summary/xrpl-tx.js";
import { built, fromHex, vectors } from "./support.js";

/* eslint-disable @typescript-eslint/no-explicit-any */
type V = any;
const solana: V = vectors("x402-exact-solana.json");
const upto: V = vectors("x402-upto-solana.json");
const charge: V = vectors("mpp-charge-solana.json");
const usdcSolana: V = vectors("mpp-charge-usdc-solana.json");
const session: V = vectors("mpp-session-solana.json");
const xrpl: V = vectors("x402-exact-xrpl.json");
const xrplCharge: V = vectors("mpp-charge-xrpl.json");
const rails: V = vectors("mpp-session-hedera-solana-xrpl.json");
const algorand: V = vectors("x402-exact-algorand.json");
const stacks: V = vectors("mpp-charge-usdc-stacks.json");
const hedera: V = vectors("x402-exact-hedera.json");
const executor: V = vectors("x402-exact-hedera-transfer-executor.json");
const lcpHedera: V = vectors("mpp-method-lcp-hedera.json");

const b64 = (s: string) => Uint8Array.from(Buffer.from(s, "base64"));
/** The message every signer of a wire signs, by the protocol package's decoder. */
const messageOf = (wireBase64: string): Uint8Array => {
  const tx = decodeSvmTx(b64(wireBase64));
  if (!("message" in tx)) throw new Error("the wire does not decode");
  return tx.message;
};
/** An XRP Ledger blob's fields, as ripple-binary-codec decodes it, without the signature's two, as the wallet is handed them. */
const txJsonOf = async (blob: string) => {
  const decoded = (await decodeBlob(blob)) as { tx: Record<string, unknown> };
  const { SigningPubKey: _k, TxnSignature: _s, ...tx } = decoded.tx;
  return tx;
};
/** A channel claim's bytes as xrpl.org's PaymentChannelClaim states them: `CLM\0`, the channel id, drops as a u64 big-endian. */
const claimBytes = (channel: string, drops: bigint) => {
  const out = new Uint8Array(44);
  out.set([0x43, 0x4c, 0x4d, 0x00], 0);
  out.set(fromHex(channel), 4);
  new DataView(out.buffer).setBigUint64(36, drops, false);
  return out;
};
const bindingOf = (id: string): Binding => BINDINGS.find((b) => b.id === id) as unknown as Binding;
/** The B2 row of `file` for `pairing`: the offer, account and inputs the pairing's build takes. */
const b2 = (file: V, pairing: string) => file.buyer.rows.find((r: V) => r.name === "B2" && r.pairing === pairing).input;

const DEVNET = solana.fixed.option.network;
const BLOCKS = { notBefore: null, notAfter: null, unit: "block" };

interface Row {
  pairing: string;
  /** Where the request and each expected member are read. */
  source: string;
  show: (request: SigningRequest, network?: string) => Shown | undefined;
  request: () => Promise<unknown>;
  /** The signer's account's network, for a request that names none. */
  network?: string;
  expect: Shown | undefined;
}

const ROWS: Row[] = [
  {
    pairing: "x402/exact/solana",
    source: "x402-exact-solana.json V2.wireBase64 (solders 0.26.0); amount, mint, network: fixed; payee: V1.destinationAta",
    show: solanaTransfer,
    request: async () => ({ kind: "solana-message", message: messageOf(solana.V2.wireBase64) }),
    network: DEVNET,
    expect: {
      amount: solana.fixed.amount,
      payees: [{ account: solana.V1.destinationAta, amount: solana.fixed.amount }],
      asset: solana.fixed.mint,
      network: DEVNET,
      validity: BLOCKS,
    },
  },
  {
    pairing: "mpp/charge/usdc/solana",
    source: "mpp-charge-usdc-solana.json V2.wireBase64 (x402-exact-solana.json's V2 wire); amount, currency: fixed.request; payee: x402-exact-solana.json V1.destinationAta",
    show: solanaTransfer,
    request: async () => ({ kind: "solana-message", message: messageOf(usdcSolana.V2.wireBase64) }),
    network: DEVNET,
    expect: {
      amount: usdcSolana.fixed.request.amount,
      payees: [{ account: solana.V1.destinationAta, amount: usdcSolana.fixed.request.amount }],
      asset: usdcSolana.fixed.request.currency,
      network: DEVNET,
      validity: BLOCKS,
    },
  },
  {
    pairing: "mpp/charge/solana",
    source: "mpp-charge-solana.json sol.expectMessageBase64 (written by hand from the Solana message format); amount, recipient, currency: sol.request",
    show: solanaTransfer,
    request: async () => ({ kind: "solana-message", message: b64(charge.sol.expectMessageBase64) }),
    network: DEVNET,
    expect: {
      amount: charge.sol.request.amount,
      payees: [{ account: charge.sol.request.recipient, amount: charge.sol.request.amount }],
      asset: charge.sol.request.currency,
      network: DEVNET,
      validity: BLOCKS,
    },
  },
  {
    pairing: "x402/upto/solana",
    source: "x402-upto-solana.json EU3.wireBase64 (solders 0.26.0); amount, payTo, asset, network: fixed.option",
    show: solanaUptoOpen,
    request: async () => ({ kind: "solana-message", message: messageOf(upto.EU3.wireBase64) }),
    network: upto.fixed.option.network,
    expect: {
      maximum: upto.fixed.option.amount,
      payees: [{ account: upto.fixed.option.payTo, amount: upto.fixed.option.amount }],
      deposit: upto.fixed.option.amount,
      asset: upto.fixed.option.asset,
      network: upto.fixed.option.network,
      validity: BLOCKS,
    },
  },
  {
    pairing: "mpp/session/solana/memo",
    source: "mpp-session-solana.json memo.expectMessageBase64 and expectChannel; cap (the deposit), recipient, currency: fixed.memoRequest",
    show: solanaSessionOpen,
    request: async () => ({
      kind: "solana-session-open",
      message: b64(session.memo.expectMessageBase64),
      size: session.memo.expectSize,
      channel: session.memo.expectChannel,
    }),
    network: DEVNET,
    expect: {
      payees: [{ account: session.fixed.memoRequest.recipient, amount: session.fixed.memoRequest.cap }],
      deposit: session.fixed.memoRequest.cap,
      asset: session.fixed.memoRequest.currency,
      network: DEVNET,
      validity: BLOCKS,
    },
  },
  {
    pairing: "x402/exact/xrpl",
    source: "x402-exact-xrpl.json V2.expectTxJson (xrpl-py 4.1.0); amount, payTo, asset, network: fixed.option; LastLedgerSequence: V2.build",
    show: xrplPayment,
    request: async () => ({ kind: "xrpl-tx", txJson: xrpl.V2.expectTxJson }),
    network: xrpl.fixed.option.network,
    expect: {
      amount: xrpl.fixed.option.amount,
      payees: [{ account: xrpl.fixed.option.payTo, amount: xrpl.fixed.option.amount }],
      asset: xrpl.fixed.option.asset,
      network: xrpl.fixed.option.network,
      validity: { notBefore: null, notAfter: String(xrpl.V2.build.lastLedgerSequence), unit: "ledger" },
    },
  },
  {
    pairing: "mpp/charge/xrpl",
    source: "mpp-charge-xrpl.json V3.blob (xrpl-py 4.1.0) decoded by ripple-binary-codec 2.11.0, its fields but the signature's, as build.case states; amount, recipient, currency: fixed.request; LastLedgerSequence: build",
    show: xrplPayment,
    request: async () => ({ kind: "xrpl-tx", txJson: await txJsonOf(xrplCharge.V3.blob) }),
    network: xrpl.fixed.option.network,
    expect: {
      amount: xrplCharge.fixed.request.amount,
      payees: [{ account: xrplCharge.fixed.request.recipient, amount: xrplCharge.fixed.request.amount }],
      asset: xrplCharge.fixed.request.currency,
      network: xrpl.fixed.option.network,
      validity: { notBefore: null, notAfter: String(xrplCharge.build.lastLedgerSequence), unit: "ledger" },
    },
  },
  {
    pairing: "mpp/charge/xrpl",
    source: "mpp-charge-xrpl.json build.issued.expectTxJson (the stock xrpl-mpp-sdk client's Payment of an issued currency): an amount with no base unit, not summarised",
    show: xrplPayment,
    request: async () => ({ kind: "xrpl-tx", txJson: xrplCharge.build.issued.expectTxJson }),
    network: xrpl.fixed.option.network,
    expect: undefined,
  },
  {
    pairing: "mpp/session/xrpl",
    source: "mpp-session-hedera-solana-xrpl.json XS2.expectTxJson (written by hand from xrpl.org), expectChannel; the first claim's drops, expectOpenPayload.amount; deposit, account: XS2",
    show: xrplSessionOpen,
    request: async () => ({
      kind: "xrpl-session-open",
      txJson: rails.XS2.expectTxJson,
      claim: { channelId: rails.XS2.expectChannel, drops: BigInt(rails.XS2.expectOpenPayload.amount), bytes: claimBytes(rails.XS2.expectChannel, BigInt(rails.XS2.expectOpenPayload.amount)) },
    }),
    network: xrpl.fixed.option.network,
    expect: {
      amount: rails.XS2.expectOpenPayload.amount,
      payees: [{ account: rails.XS2.expectTxJson.Destination, amount: rails.XS2.expectOpenPayload.amount }],
      deposit: rails.XS2.deposit,
      closableBy: [rails.XS2.account, rails.XS2.expectTxJson.Destination],
      asset: "XRP",
      network: xrpl.fixed.option.network,
      validity: { notBefore: null, notAfter: String(rails.XS2.lastLedgerSequence), unit: "ledger" },
    },
  },
  {
    pairing: "mpp/session/xrpl",
    source: "mpp-session-hedera-solana-xrpl.json XS2.withCancelAfter.expectTxJson; its end in Unix seconds, XS2.expectUntil",
    show: xrplSessionOpen,
    request: async () => ({
      kind: "xrpl-session-open",
      txJson: rails.XS2.withCancelAfter.expectTxJson,
      claim: { channelId: rails.XS2.expectChannel, drops: BigInt(rails.XS2.expectOpenPayload.amount), bytes: claimBytes(rails.XS2.expectChannel, BigInt(rails.XS2.expectOpenPayload.amount)) },
    }),
    network: xrpl.fixed.option.network,
    expect: {
      amount: rails.XS2.expectOpenPayload.amount,
      payees: [{ account: rails.XS2.expectTxJson.Destination, amount: rails.XS2.expectOpenPayload.amount }],
      end: String(rails.XS2.expectUntil),
      deposit: rails.XS2.deposit,
      closableBy: [rails.XS2.account, rails.XS2.expectTxJson.Destination],
      asset: "XRP",
      network: xrpl.fixed.option.network,
      validity: { notBefore: null, notAfter: String(rails.XS2.lastLedgerSequence), unit: "ledger" },
    },
  },
  {
    pairing: "x402/exact/algorand",
    source: "x402-exact-algorand.json V2.expectBytesToSign (py-algorand-sdk 2.12.0); amount, payTo, asset, network: fixed.O; firstValid: fixed.params; lastValid: V3.expectReference",
    show: algorandTransfer,
    request: async () => ({ kind: "algorand-txn", bytes: fromHex(algorand.V2.expectBytesToSign) }),
    expect: {
      amount: algorand.fixed.O.amount,
      payees: [{ account: algorand.fixed.O.payTo, amount: algorand.fixed.O.amount }],
      asset: algorand.fixed.O.asset,
      network: algorand.fixed.O.network,
      validity: { notBefore: algorand.fixed.params.firstValid, notAfter: algorand.V3.expectReference.lastValid, unit: "round" },
    },
  },
  {
    pairing: "mpp/charge/usdc/stacks",
    source: "mpp-charge-usdc-stacks.json buyer B2's offer, account and inputs, through the pairing's build; amount, recipient, contract, network: fixed",
    show: stacksTransfer,
    request: async () => {
      const r = b2(stacks, "mpp/charge/usdc/stacks");
      return (await built(bindingOf("mpp/charge/usdc/stacks"), r.doc, r.account, r.inputs)).request;
    },
    expect: {
      amount: stacks.fixed.amount,
      payees: [{ account: stacks.fixed.recipient, amount: stacks.fixed.amount }],
      asset: stacks.fixed.contract,
      network: stacks.fixed.network,
      validity: { notBefore: null, notAfter: null, unit: "seconds" },
    },
  },
  {
    pairing: "x402/exact/hedera",
    source: "x402-exact-hedera.json V2.expectBodyBytes; payer, payee, rows, valid start and duration, network: V2.expectReference",
    show: hederaTransfer,
    request: async () => ({ kind: "hedera-body", bodyBytes: fromHex(hedera.V2.expectBodyBytes) }),
    network: hedera.V2.expectReference.network,
    expect: {
      amount: hedera.fixed.O.amount,
      payees: [{ account: hedera.V2.expectReference.payee, amount: hedera.fixed.O.amount }],
      asset: hedera.fixed.O.asset,
      network: hedera.V2.expectReference.network,
      validity: {
        notBefore: hedera.fixed.validStart.seconds,
        notAfter: String(Number(hedera.fixed.validStart.seconds) + hedera.V2.expectReference.validDuration),
        unit: "seconds",
      },
    },
  },
  {
    pairing: "mpp/charge/lcp/hedera",
    source: "mpp-method-lcp-hedera.json build[0].expectBodyBytes (the same body as x402-exact-hedera.json V2); expected as that row's",
    show: hederaTransfer,
    request: async () => ({ kind: "hedera-body", bodyBytes: fromHex(lcpHedera.build[0].expectBodyBytes) }),
    network: hedera.V2.expectReference.network,
    expect: {
      amount: hedera.fixed.O.amount,
      payees: [{ account: hedera.V2.expectReference.payee, amount: hedera.fixed.O.amount }],
      asset: hedera.fixed.O.asset,
      network: hedera.V2.expectReference.network,
      validity: {
        notBefore: hedera.fixed.validStart.seconds,
        notAfter: String(Number(hedera.fixed.validStart.seconds) + hedera.V2.expectReference.validDuration),
        unit: "seconds",
      },
    },
  },
  {
    pairing: "x402/exact/hedera/transfer-executor",
    source: "x402-exact-hedera-transfer-executor.json build.expectRequest",
    show: hederaExecutor,
    request: async () => executor.build.expectRequest,
    expect: {
      amount: executor.build.expectRequest.amount,
      payees: [{ account: executor.build.expectRequest.payTo, amount: executor.build.expectRequest.amount }],
      asset: executor.build.expectRequest.asset,
      network: executor.build.expectRequest.network,
      validity: { notBefore: null, notAfter: String(executor.build.expectRequest.validBefore), unit: "seconds" },
      grant: {
        executors: executor.build.expectRequest.executors,
        asset: executor.build.expectRequest.asset,
        payTo: executor.build.expectRequest.payTo,
        amount: executor.build.expectRequest.amount,
      },
    },
  },
];

describe("the summaries of the Solana, XRP Ledger, Algorand, Stacks and Hedera requests", () => {
  for (const row of ROWS) {
    it(`${row.pairing}: ${row.source}`, async () => {
      expect(SUMMARIES.get(row.pairing)?.show).toBe(row.show);
      const request = (await row.request()) as SigningRequest;
      expect(row.show(request, row.network)).toEqual(row.expect);
      if (row.network === undefined && row.expect !== undefined) {
        // A request that names its own network is summarised by the gate's registry as it stands.
        const atr = Uint8Array.of(0x7b, 0x7d);
        expect(summaryOf(row.pairing, request, atr)).toEqual({ ...row.expect, atr });
      }
    });
  }
});
