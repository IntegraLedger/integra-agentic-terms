export {
  type Disposition,
  decideOutcome,
  foldDispositions,
  type GateDecision,
  type StepStatus,
} from "./decision.js";
export { evaluate, type GatePorts } from "./evaluate.js";
export {
  type CachingFetcherConfig,
  type FetchedTerms,
  type HostLookup,
  makeCachingFetcher,
  nodeDnsLookup,
  type ResolvedAddress,
  type TermsFetcher,
} from "./fetch.js";
export { type FingerprintOutcome, recomputeAndCompare } from "./fingerprint.js";
export { InMemoryOrc4Log, type Orc4Entry, type Orc4Log } from "./log.js";
export { type MechanicalPorts, verifySettled } from "./mechanical.js";
export {
  type BuyerPolicy,
  evaluatePolicy,
  type PolicyResult,
} from "./policy.js";
export {
  type GateProposal,
  type ProposalContext,
  parseProposalFromChallenge,
} from "./proposal.js";
export {
  ACK_DID_METHODS,
  type AckReceiptContribution,
  type AckReceiptFacts,
  ackReceiptContribution,
  parseAckReceipt,
} from "./proposal-ack.js";
export { parseProposalFromAcpCheckout } from "./proposal-acp.js";
export {
  AP2_HALT_POINT,
  type Ap2HaltPoint,
  type Ap2ProposalContext,
  type Ap2Step,
  assertBeforeAp2HaltPoint,
  isAp2SigningStep,
  parseProposalFromAp2Envelope,
} from "./proposal-ap2.js";
export { parseProposalFromMppRequest } from "./proposal-mpp.js";
export {
  ACP_SESSION_STATUS,
  type AdvertisedTerms,
  type AdvertisedTermsUrl,
  detectProtocol,
  matchProtocols,
  PROPOSAL_PARSERS,
  PROTOCOL_DISCRIMINANTS,
  type ProposalParser,
  type ProtocolDiscriminant,
  parseableProtocols,
  parseProposalUniversal,
  readAdvertisedTerms,
  VI_OPEN_MANDATE_VCT,
} from "./proposal-universal.js";
export {
  type GatedSigner,
  type TransactResult,
  transact,
} from "./transact.js";
