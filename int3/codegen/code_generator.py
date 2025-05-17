from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING

from int3.ir import IrBranch, IrOperation

from .gadget import Gadget

if TYPE_CHECKING:
    from int3.compilation import Block


@dataclass
class CodeGenerator(ABC):
    def emit_asm(self, blocks: list["Block"]) -> bytes:
        # Process blocks into a half-compiled form. We hold off on finalizing
        # branches, jumps, and calls, TODO.
        # TODO

        # Re-arrange blocks to avoid bad bytes in relocations.
        # TODO

        # Stitch it all together.
        # TODO

        return b"TODO"

    def _map_variables(self, block: "Block"): ...

    def _translate_ir_operation(self, operation: IrBranch | IrOperation): ...

    @abstractmethod
    def emit_mov(self) -> Gadget: ...

    @abstractmethod
    def emit_branch(self) -> Gadget: ...

    @abstractmethod
    def emit_call(self) -> Gadget: ...

    @abstractmethod
    def emit_jump(self) -> Gadget: ...

    @abstractmethod
    def emit_syscall(self) -> Gadget: ...
