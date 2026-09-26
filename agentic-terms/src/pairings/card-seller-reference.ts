/** The buyer piece for `card/seller-reference`: nothing the buyer signs carries the hash, so the gate confirms only. */
import { sellerReferencePiece } from "./card.js";

export const cardSellerReference = sellerReferencePiece("card/seller-reference");
