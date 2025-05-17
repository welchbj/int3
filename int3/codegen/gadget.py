from dataclasses import dataclass

from .implication import Implication


@dataclass(frozen=True)
class Gadget:
    implications: tuple[Implication]
