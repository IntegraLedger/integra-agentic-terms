"""The buyer piece for mpp/session/xrpl/stock: the first challenge, in document order, that offers the pairing. The
buyer's stock client opens the channel itself, out of band, with no memo, so nothing is handed to the signer: the proof
of the hash is the agreement payment, on the session's own network, paid before the stock client opens the channel,
from the account that opens it. The challenge stays in the choice, so the agreement is paid on its network. The
protocol package's pairings_of names this pairing beside mpp/session/xrpl for one challenge: the binding the caller
gives decides which of the two is paid."""

from ..bindings.mpp_session_xrpl_stock import ID
from ._mpp import MppConfirmOnlyPiece

PIECE = MppConfirmOnlyPiece(ID)
