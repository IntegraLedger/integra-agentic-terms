/**
 * The buyer piece for `mpp/session/solana/stock`, MPP's `session` intent with the stock method `solana` under any
 * challenge but the one the memo session takes, at coverage `none`: the first challenge, in document order, that offers
 * the pairing. The buyer's stock client composes, signs and broadcasts the `open` itself, with a random salt, so nothing
 * the buyer signs carries the hash, the protocol package builds nothing, and nothing is handed to the signer. The proof
 * of the hash is the agreement payment, on the session's own network, paid before the stock client opens the channel,
 * from the account that opens it, the `open`'s payer, whose token account funds the deposit, never its
 * `authorizedSigner` (the protocol package's profile `mpp-session-hedera-solana-xrpl.md`, clause 2); the challenge
 * stays in the choice, so the agreement is paid on its network.
 */
import { mppConfirmOnlyPiece } from "./mpp-confirm-only.js";

export const mppSessionSolanaStock = mppConfirmOnlyPiece("mpp/session/solana/stock");
