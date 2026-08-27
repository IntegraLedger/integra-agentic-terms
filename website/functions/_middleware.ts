import { siteConfig } from "../src/lib/site";

/**
 * Canonical host enforcement.
 *
 * The Pages project answers on the apex and on its `.pages.dev` alias, which would otherwise
 * be two independently indexable copies of the same site, each declaring the other's
 * canonical. This folds the alias into the apex with a permanent 301, preserving path and
 * query. It has to live here: the alias is on Cloudflare's zone, not ours, so no redirect
 * rule on `integraledger.com` can reach it.
 *
 * Preview deployments (`<hash>.integra-agentic-terms.pages.dev`) and local dev are matched
 * exactly, NOT by suffix, so they keep working untouched.
 *
 * The fold is armed by `CANONICAL_HOST_ATTACHED` in wrangler.toml, and it ships `"false"`
 * until the apex is attached to the Pages project and resolving: a 301 to a host that does
 * not answer would take the alias — today the only host that answers — down with it. Flip
 * it once, redeploy, and the alias folds. See README.md "Deploying".
 */

interface Env {
  CANONICAL_HOST_ATTACHED?: string;
}

const CANONICAL_HOST = new URL(siteConfig.url).hostname;

const REDIRECT_HOSTS = new Set([`${siteConfig.github.repo}.pages.dev`]);

// The same value public/_headers sets on every ordinary response, restated so the 301
// carries it too. No `preload`: only a registrable domain can be preloaded, and this is a
// subdomain of one.
const HSTS = "max-age=63072000; includeSubDomains";

export const onRequest: PagesFunction<Env> = async (context) => {
  const url = new URL(context.request.url);

  if (
    context.env.CANONICAL_HOST_ATTACHED === "true" &&
    REDIRECT_HOSTS.has(url.hostname)
  ) {
    url.hostname = CANONICAL_HOST;
    url.protocol = "https:";
    url.port = "";
    return new Response(null, {
      status: 301,
      headers: {
        Location: url.toString(),
        "Strict-Transport-Security": HSTS,
      },
    });
  }

  return context.next();
};
