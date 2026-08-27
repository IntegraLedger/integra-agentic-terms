import type { HaltClass } from "@integraledger/lcp-binding-core";

export interface Orc4Entry {
  readonly timestamp: string;
  readonly decision: "proceed" | "decline" | "escalate";
  readonly haltClass?: HaltClass;
  readonly code: string;
  readonly detail: string;
  readonly atrHash?: string;
  /**
   * The discovery document the proposal pointed at — the terms this decision was reached about.
   *
   * WITHOUT IT AN ENTRY NAMES A VERDICT AND NOT ITS SUBJECT. `atrHash` alone does not identify the
   * document: on the decision that matters most — a fingerprint mismatch — the advertised hash is by
   * construction NOT the hash of what was served, so a reader holding only that value cannot say which
   * document disagreed with it. A seller told "your terms did not match" and given a hash it cannot
   * reproduce learns nothing it can act on; given the URL, it can fetch the bytes and see.
   *
   * Optional for the same reason `atrHash` is: this is the sink's input type, and a producer other than
   * `evaluate` — a mechanical verification, say — may legitimately have no document to name. `evaluate`
   * always sets it.
   */
  readonly legalContextUrl?: string;
}
export interface Orc4Log {
  append(e: Orc4Entry): void;
}
/** A real, complete in-memory ORC-4 sink (not a mock) — a deployment injects a durable one. */
export class InMemoryOrc4Log implements Orc4Log {
  readonly entries: Orc4Entry[] = [];
  append(e: Orc4Entry): void {
    this.entries.push(e);
  }
}
