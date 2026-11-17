/**
 * The readers the EVM summaries share: a request's members read as the signer is handed them, each answering undefined
 * for a value of another form, so a request a summary cannot read has no summary.
 */

export function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

const DECIMAL = /^[0-9]{1,78}$/;

/** A non-negative integer as a decimal string: a bigint, a safe integer, or a decimal string; else undefined. */
export function decimal(v: unknown): string | undefined {
  if (typeof v === "bigint") return v >= 0n ? v.toString() : undefined;
  if (typeof v === "number") return Number.isSafeInteger(v) && v >= 0 ? String(v) : undefined;
  return typeof v === "string" && DECIMAL.test(v) ? v : undefined;
}

/** A 20-byte address as `0x` and 40 hex digits, as the request writes it; else undefined. */
export function address(v: unknown): string | undefined {
  return typeof v === "string" && /^0x[0-9a-fA-F]{40}$/.test(v) ? v : undefined;
}

/** Whether two addresses name one account, compared without their letters' case. */
export const sameAddress = (a: string, b: string): boolean => a.toLowerCase() === b.toLowerCase();

/** Whether an EIP-712 struct type's members are exactly `fields`, each `[name, type]`, in that order. */
export function typeIs(members: unknown, fields: readonly (readonly [string, string])[]): boolean {
  if (!Array.isArray(members) || members.length !== fields.length) return false;
  return fields.every(([name, type], i) => {
    const m: unknown = members[i];
    return isObject(m) && Object.keys(m).length === 2 && m["name"] === name && m["type"] === type;
  });
}
