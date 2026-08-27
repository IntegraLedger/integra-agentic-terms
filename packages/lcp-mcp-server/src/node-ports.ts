import {
  makeCachingFetcher,
  nodeDnsLookup,
} from "@integraledger/agentic-terms";
import type { LcpMcpPorts } from "./ports.js";

/** The environment variable a deployment states its own reverse-domain namespace in. */
export const REVERSE_DOMAIN_ENV = "LCP_MCP_REVERSE_DOMAIN";

/** The wall clock as an ISO-8601 instant — the `now` port the terms fetcher requires. */
export function isoNow(): string {
  return new Date().toISOString();
}

/**
 * The Node wiring: the real, guarded terms fetcher plus whatever the environment states.
 *
 * The fetcher is `agentic-terms`'s — HTTPS-only, `redirect: "error"`, every resolved address checked public
 * unicast on every network fetch, body capped while streaming, LCP §2.6 cache discipline. This server
 * fetches URLs a COUNTERPARTY chose, so that is not hardening, it is the minimum: bare `fetch` here would
 * turn `lcp_verify_before_pay` into an SSRF primitive an agent can be talked into aiming anywhere.
 *
 * `LCP_MCP_REVERSE_DOMAIN` is absent by default and stays absent. It is only needed by placements whose
 * carrier is namespaced under the deployment's own domain (Mastercard VI's custom Layer-2 constraint type),
 * and LCP §8 canonizes no per-protocol integration profile — so a default here would write Integra's domain
 * into someone else's signed document in every deployment that forgot to set it. Unset, that one placement
 * throws and names what is missing; every other tool is unaffected.
 */
export function nodePorts(
  env: Readonly<Record<string, string | undefined>>,
): LcpMcpPorts {
  const reverseDomain = env[REVERSE_DOMAIN_ENV];
  return {
    fetcher: makeCachingFetcher({
      httpFetch: fetch,
      now: isoNow,
      lookup: nodeDnsLookup,
    }),
    ...(reverseDomain !== undefined ? { deployment: { reverseDomain } } : {}),
  };
}
