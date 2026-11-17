"""The buyer piece for mpp/session/hedera/stock: the first challenge, in document order, that offers the pairing. The
buyer's stock client sends the escrow's approve and open itself, with a random salt, so nothing is handed to the
signer: the proof of the hash is the agreement payment, on the session's own network, paid before the stock client
opens the channel, from the account that opens it. The challenge stays in the choice, so the agreement is paid on its
network."""

from ..bindings.mpp_session_hedera_stock import ID
from ._mpp import MppConfirmOnlyPiece

PIECE = MppConfirmOnlyPiece(ID)
