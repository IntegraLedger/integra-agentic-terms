import type { TermsFetcher } from "@integraledger/agentic-terms";
import type { PlacementDeployment } from "@integraledger/lcp-placements";

/**
 * What a deployment supplies before this server can serve anything.
 *
 * NO DEFAULTS, and both entries are the reason. The fetcher is the buyer gate's own HTTPS-only,
 * SSRF-guarded, size-capped, LCP §2.6-cached implementation (`agentic-terms`'s `makeCachingFetcher`) — the
 * URLs this server fetches are chosen by a *counterparty*, so a server that quietly defaulted to bare
 * `fetch` would silently drop the guard that makes those fetches safe. `nodePorts` wires the real one for a
 * Node deployment; a Workers deployment supplies its own `lookup`.
 *
 * `deployment` is genuinely optional rather than defaulted: eight of the nine registered placements are
 * singletons needing nothing from it, and only Mastercard VI's namespaced factory requires a reverse domain.
 * Omitting it makes `lcp_place_reference` throw for that ONE protocol, naming what is missing — which is the
 * registry's own rule, not a second copy of it here.
 */
export interface LcpMcpPorts {
  /** Fetches terms and discovery documents. See `@integraledger/agentic-terms`'s `makeCachingFetcher`. */
  readonly fetcher: TermsFetcher;
  /** The deployment's own reverse-domain namespace, for namespaced placement registrations. */
  readonly deployment?: PlacementDeployment;
}
