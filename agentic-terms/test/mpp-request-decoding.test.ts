// An MPP challenge's request is read as the protocol package reads it: base64url without padding (RFC 4648 section 5),
// whose final character's unused bits are zero (RFC 4648 section 3.5), at most 8 KiB decoded; UTF-8 whose leading byte
// order mark is kept as a character, so no JSON text follows one (RFC 8259 section 8.1); one JSON object nested at most
// 16 levels deep, with an RFC 8785 form. Each case's expected answer is the protocol package's own `pairingsOf` on the
// same challenge: `mpp/request-malformed` for each refused form, and the pairing for each control. The challenge is
// mpp-challenge.json's C_E.
import { describe, expect, it } from "vitest";
import { pairingsOf, type MppChallenge } from "@integraledger/lcp/mpp";
import { requestOf } from "../src/pairings/mpp.js";
import { vectors } from "./support.js";

// Vector files are read as loose JSON data; each row names the fields it uses.
type Loose = any;

const V = vectors<Loose>("mpp-challenge.json");
const f = V.fixed;
const PAIRING = "mpp/charge/evm/authorization";
const BOM = Uint8Array.of(0xef, 0xbb, 0xbf);
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const utf8 = (s: string) => Buffer.from(s, "utf8");
const b64u = (b: Uint8Array) => Buffer.from(b).toString("base64url");
const text = JSON.stringify(JSON.parse(f.R_E));

/** The vector's request text with one more member. */
const withMember = (name: string, json: string) => `${text.slice(0, -1)},${JSON.stringify(name)}:${json}}`;
/** The vector's request text, with a string member that makes it exactly `n` UTF-8 bytes. */
function ofBytes(n: number): string {
  const short = utf8(withMember("pad", '""')).length;
  return withMember("pad", JSON.stringify("x".repeat(n - short)));
}
/** The vector's request text with a member whose innermost object sits `depth` levels down, the request the first. */
const nested = (depth: number) => withMember("deep", `${'{"a":'.repeat(depth - 2)}{}${"}".repeat(depth - 2)}`);
/** A request text whose UTF-8 length is not a multiple of three, so its base64url ends in unused bits. */
const odd = utf8(text).length % 3 === 0 ? withMember("x", '"y"') : text;
/** The base64url of `t` with its final character's lowest unused bit set: the same bytes, written another way. */
function bent(t: string): string {
  const o = b64u(utf8(t));
  return o.slice(0, -1) + ALPHABET[ALPHABET.indexOf(o.at(-1)!) | 1]!;
}

const refused: [string, string][] = [
  ["a byte order mark before its JSON text", b64u(Buffer.concat([BOM, utf8(text)]))],
  ["the padded form", `${b64u(utf8(odd))}${"=".repeat((4 - (b64u(utf8(odd)).length % 4)) % 4)}`],
  ["a final character with a non-zero unused bit", bent(odd)],
  ["8,193 bytes decoded", b64u(utf8(ofBytes(8193)))],
  ["a member nested 17 levels deep", b64u(utf8(nested(17)))],
  ["an escaped lone surrogate, which has no RFC 8785 form", b64u(utf8(withMember("s", '"\\ud800"')))],
];
const read: [string, string][] = [
  ["the vector's request", b64u(utf8(text))],
  ["8,192 bytes decoded", b64u(utf8(ofBytes(8192)))],
  ["a member nested 16 levels deep", b64u(utf8(nested(16)))],
];

const issued = (request: string) =>
  ({ realm: f.realm, method: "evm", intent: "charge", request, expires: f.expires }) as MppChallenge;

describe("an MPP challenge's request", () => {
  it("each refused form differs from the canonical encoding, and the padded and bent forms hold the same bytes", () => {
    const canonical = b64u(utf8(odd));
    expect(refused[1]![1]).not.toBe(canonical);
    expect(refused[2]![1]).not.toBe(canonical);
    expect(Buffer.from(refused[1]![1], "base64url")).toEqual(utf8(odd));
    expect(Buffer.from(refused[2]![1], "base64url")).toEqual(utf8(odd));
    expect(utf8(ofBytes(8193)).length).toBe(8193);
  });

  it.each(read)("%s: read, as the protocol package reads it", (_, request) => {
    expect(pairingsOf(issued(request))).toContain(PAIRING);
    expect(requestOf(issued(request))).toEqual(JSON.parse(Buffer.from(request, "base64url").toString("utf8")));
  });

  it.each(refused)("%s: not read, as the protocol package answers mpp/request-malformed", (_, request) => {
    expect(pairingsOf(issued(request))).toEqual({ refused: true, code: "mpp/request-malformed" });
    expect(requestOf(issued(request))).toBeUndefined();
  });
});
