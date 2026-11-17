"""The buyer pieces for mpp/charge/tempo/split-memo, the pull form, and mpp/charge/tempo/split-memo/push: the first
challenge, in document order, that offers the pairing on the account's EVM network, as MPP's network reads it (eip155:
and the challenge's methodDetails.chainId). The resource server places H as the memo of a one-unit split in the
challenge, and the buyer's stock MPP client builds and signs the Tempo transaction from the challenge, copying each
split's memo into its transfer (lcp profile mpp-charge-tempo-split-memo.md, rules 1 and 5). The binding builds nothing
and nothing is handed to the signer: the gate compares the ATR, and check reads H from the transaction the buyer's
client signed. On the pull form the resource server's settler broadcasts that transaction; on the push form the
buyer's client broadcasts it and names it by its hash, so check reads H with the landed receipt the caller's own reader
read for it, given as landed: the transaction's hash, block number, logs and signed bytes."""

from .._types import Advertised, Chosen, Inputs, Json, Refusal
from ..bindings._mpp import network
from ..bindings.mpp_charge_tempo_split_memo import PULL, PUSH
from ._common import account_of
from ._mpp import EVM_ADDRESS, MppConfirmOnlyPiece, challenges_of, pairings_of_placed


class SplitMemoPiece(MppConfirmOnlyPiece):
    """A confirm-only piece that takes a challenge only on the account's EVM network."""

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        a = account_of(account)
        if a is None or a.namespace != "eip155" or EVM_ADDRESS.fullmatch(a.address) is None:
            return Refusal("mpp/no-payable-option")
        challenge = next(
            (c for c in challenges_of(read) if self.pairing in pairings_of_placed(c) and network(c) == a.network), None
        )
        if challenge is None:
            return Refusal("mpp/no-payable-option")
        return Chosen(pairing=self.pairing, choice={"challenge": challenge, "now": now}, ref=ref)


PULL_PIECE = SplitMemoPiece(PULL)
PUSH_PIECE = SplitMemoPiece(PUSH)
