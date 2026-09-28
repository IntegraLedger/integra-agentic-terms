#!/usr/bin/env node
/**
 * Serves the buyer tools over stdio with no signer: `atr_confirm`, `atr_finish`, `atr_check` and the channel tools. The
 * tools fetch over https, from public addresses only.
 */
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { createBuyerServer } from "./index.js";
import { publicFetch } from "./public-fetch.js";

serveStdio(() => createBuyerServer({ fetch: publicFetch }), { legacy: "serve" });
