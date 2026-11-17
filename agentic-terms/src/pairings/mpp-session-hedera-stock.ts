/**
 * The buyer piece for `mpp/session/hedera/stock`, MPP's `session` intent with the stock method `hedera`, at coverage
 * `none`: the first challenge, in document order, that offers the pairing. The buyer's stock client sends the escrow's
 * `approve` and `open` itself, with a random salt, so nothing the buyer signs carries the hash, the protocol package
 * builds nothing, and nothing is handed to the signer. The proof of the hash is the agreement payment, on the session's
 * own network, paid before the stock client opens the channel, from the account that opens it (the protocol package's
 * profile `mpp-session-hedera-solana-xrpl.md`, clause 1); the challenge stays in the choice, so the agreement is paid
 * on its network.
 */
import { mppConfirmOnlyPiece } from "./mpp-confirm-only.js";

export const mppSessionHederaStock = mppConfirmOnlyPiece("mpp/session/hedera/stock");
