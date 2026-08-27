/** LCP §2.1: the one location a service publishes its legal context at. */
export const WELL_KNOWN_PATH = "/.well-known/legal-context.json";

/**
 * The canonical discovery URL for a service, from either a bare origin or the well-known URL itself.
 *
 * IDEMPOTENT over both spellings on purpose: an agent that already holds the full
 * `https://seller.example/.well-known/legal-context.json` and one that holds only `https://seller.example`
 * are the same caller a moment apart, and appending the path twice would 404 against a conformant seller.
 *
 * PARSED, NEVER CONCATENATED, and the refusals are why. Appending to the raw string put the well-known path
 * INSIDE whatever the input already carried: `https://x.example?level=3` became
 * `https://x.example?level=3/.well-known/legal-context.json`, which fails on the wire as a broken discovery
 * document at the service root instead of as the input error it is. So the input is parsed, and three
 * shapes are refused BY NAME rather than silently rewritten:
 *
 *  - **A query or a fragment.** LCP §2.1 defines the well-known URI with no parameters, and a query a
 *    conformant seller ignores is a request for behaviour the standard does not define — appending one as
 *    a private hint only works against a server that already agreed to read it. The level a document
 *    satisfies is read off the document.
 *  - **Credentials in the authority.** `URL`'s `origin` drops them, so parsing `https://u:p@h.example`
 *    would hand back a URL addressed differently from the one the caller supplied — the one thing
 *    concatenation got right. Silently changing who is being talked to is worse than refusing.
 *  - **No network origin at all.** `mailto:`, `data:`, `file:`, `urn:` — each accepted by the tools'
 *    `z.url()`, and none of them has a well-known location.
 *
 * SCHEME IS NOT CHECKED HERE. `agentic-terms`'s fetcher is HTTPS-only and refuses `http:` on the way out; a
 * second copy of that rule in this function would be duplicated truth with nothing keeping the two in step.
 *
 * A THROW is the right shape inside a tool handler: the MCP SDK surfaces a handler throw as an
 * `isError: true` `tools/call` result, so the model reads the refusal rather than a transport failure.
 */
export function legalContextUrl(serviceUrl: string): string {
  const url = new URL(serviceUrl);
  if (url.origin === "null")
    throw new Error(
      `not a service URL — \`${serviceUrl}\` has no network origin, so it has no well-known location`,
    );
  if (url.search !== "" || url.hash !== "")
    throw new Error(
      `not a service URL — \`${serviceUrl}\` carries a query or fragment, and LCP §2.1 defines the well-known URI with neither`,
    );
  if (url.username !== "" || url.password !== "")
    throw new Error(
      `not a service URL — \`${serviceUrl}\` carries credentials in its authority, which the well-known location does not preserve`,
    );
  const path = url.pathname.replace(/\/+$/, "");
  return path.endsWith(WELL_KNOWN_PATH)
    ? `${url.origin}${path}`
    : `${url.origin}${path}${WELL_KNOWN_PATH}`;
}
