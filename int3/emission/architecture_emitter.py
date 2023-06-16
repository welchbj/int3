from abc import ABC, abstractmethod
from typing import Generic, TypeVar

from int3.gadget import Gadget
from int3.registers import Immediate, IntImmediate, Registers

from .emitter import Emitter


class ArchitectureEmitter(Emitter, ABC, Generic[Registers]):
    @abstractmethod
    def literal_mov(self, dst: Registers, src: Registers | IntImmediate) -> Gadget:
        ...

    @abstractmethod
    def literal_load(self, dst: Registers, src_ptr: Registers, offset: int = 0) -> Gadget:
        ...

    @abstractmethod
    def literal_push(self, value: Registers | Immediate) -> Gadget:
        ...

    @abstractmethod
    def literal_pop(self, result: Registers | None = None) -> Gadget:
        ...

    @abstractmethod
    def literal_add(self, dst: Registers, operand: Registers | IntImmediate) -> Gadget:
        ...

    @abstractmethod
    def literal_sub(self, dst: Registers, operand: Registers | IntImmediate) -> Gadget:
        ...

    @abstractmethod
    def literal_xor(self, dst: Registers, operand: Registers | IntImmediate) -> Gadget:
        ...

    @abstractmethod
    def literal_neg(self, dst: Registers) -> Gadget:
        ...

    @abstractmethod
    def literal_call(self, target: Registers) -> Gadget:
        ...

    @abstractmethod
    def literal_breakpoint(self) -> Gadget:
        ...

    # TODO: Shifts?

    def literal_label(self, name: str) -> Gadget:
        return Gadget(f"{name}: ")
