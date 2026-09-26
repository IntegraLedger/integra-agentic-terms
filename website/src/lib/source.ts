import { loader, multiple } from "fumadocs-core/source";
import { api, docs } from "@/.source/server";

/** The site's pages: the repository's docs/ at the root, and the generated API pages under /api. */
export const source = loader({
  baseUrl: "/",
  source: multiple({
    docs: docs.toFumadocsSource(),
    api: api.toFumadocsSource(),
  }),
});

export type Page = ReturnType<typeof source.getPages>[number];
