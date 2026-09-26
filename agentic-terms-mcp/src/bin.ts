#!/usr/bin/env node
/** Serves the buyer tools over stdio with no signer: `atr_confirm`, `atr_finish` and `atr_check`. */
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { createBuyerServer } from "./index.js";

serveStdio(() => createBuyerServer({ fetch: globalThis.fetch }), { legacy: "serve" });
