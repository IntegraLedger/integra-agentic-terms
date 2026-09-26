"""The gate's buyer piece for x402/exact/polkadot/lcp-assets-remark: the request is the profile's call, which the wallet
signs as a v4 extrinsic with its own extensions and answers as the extrinsic's bytes in 0x hex."""

from typing import Any

from .._types import Advertised, Chosen, Inputs, Refusal, Signature
from ..bindings._ss58 import ss58_decode
from ..bindings.x402_exact_polkadot_lcp_assets_remark import ID
from ._base import BasePiece
from ._common import bytes_of
from ._x402_account_rails import chosen_choice, identified, rail_option


class X402ExactPolkadotLcpAssetsRemarkPiece(BasePiece):
    pairing = ID

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Any) -> Chosen | Refusal:
        o = rail_option(read, account, ("polkadot",), ID, lambda a: ss58_decode(a) is not None)
        if isinstance(o, Refusal):
            return o
        return Chosen(pairing=ID, choice={"required": o.required, "accepted": o.accepted}, ref=ref)

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any:
        return chosen_choice(chosen)

    def request(self, unsigned: Any) -> dict[str, Any]:
        request: dict[str, Any] = unsigned.request
        return request

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
        extrinsic = bytes_of(signature)
        if extrinsic is None or len(extrinsic) == 0:
            return Refusal("x402/signature-malformed")
        return identified(unsigned.complete(extrinsic), chosen)


PIECE = X402ExactPolkadotLcpAssetsRemarkPiece()
