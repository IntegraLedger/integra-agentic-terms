/**
 * The buyer piece for `mpp/session/xrpl/stock`, the stock XRPL session, at coverage `none`: the first challenge, in
 * document order, that offers the pairing. The buyer's stock client opens the channel itself, out of band, with no
 * memo, and presents vouchers that name it, so nothing the buyer signs carries the hash, the protocol package builds
 * nothing, and nothing is handed to the signer. The proof of the hash is the agreement payment, on the session's own
 * network, paid before the stock client opens the channel, from the account that opens it (the protocol package's
 * profile `mpp-session-hedera-solana-xrpl.md`, clause 3); the challenge stays in the choice, so the agreement is paid
 * on its network. The protocol package's `pairingsOf` names this pairing beside `mpp/session/xrpl` for one challenge:
 * the binding the caller gives decides which of the two is paid.
 */
import { mppConfirmOnlyPiece } from "./mpp-confirm-only.js";

export const mppSessionXrplStock = mppConfirmOnlyPiece("mpp/session/xrpl/stock");
