from abc import ABC, abstractmethod
from typing import Generic

from int3.gadget import Gadget
from int3.registers import Immediate, IntImmediate, Registers

from .emitter import Emitter


class ArchitectureEmitter(Emitter, ABC, Generic[Registers]):
    @abstractmethod
    def mov(self, dst: Registers, src: Registers | IntImmediate) -> Gadget:
        ...

    @abstractmethod
    def load(self, dst: Registers, src_ptr: Registers, offset: int = 0) -> Gadget:
        ...

    @abstractmethod
    def push(self, value: Registers | Immediate) -> Gadget:
        ...

    @abstractmethod
    def pop(self, result: Registers | None = None) -> Gadget:
        ...

    @abstractmethod
    def add(self, dst: Registers, operand: Registers | IntImmediate) -> Gadget:
        ...

    @abstractmethod
    def sub(self, dst: Registers, operand: Registers | IntImmediate) -> Gadget:
        ...

    @abstractmethod
    def xor(self, dst: Registers, operand: Registers | IntImmediate) -> Gadget:
        ...

    @abstractmethod
    def neg(self, dst: Registers) -> Gadget:
        ...

    @abstractmethod
    def call(self, target: Registers) -> Gadget:
        ...

    @abstractmethod
    def breakpoint(self) -> Gadget:
        ...

    # TODO: Shifts?

    def label(self, name: str) -> Gadget:
        return Gadget(f"{name}: ")
