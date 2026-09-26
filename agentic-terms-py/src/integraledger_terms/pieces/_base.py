"""What every buyer piece shares: the choice is Chosen's own, the build is the binding's, the payment is sent as it
was completed, and the signer moves nothing before the gate reads what was signed."""

from typing import Any

from .._core import AtrHash
from .._types import Binding, Chosen, Json


class BasePiece:
    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any:
        return chosen.choice

    def build(self, binding: Binding, choice: Any, h: AtrHash) -> Any:
        return binding.build(choice, h)

    def sent(self, signed: dict[str, Any]) -> dict[str, Any]:
        return signed

    def moves(self, request: Json) -> bool:
        return False
