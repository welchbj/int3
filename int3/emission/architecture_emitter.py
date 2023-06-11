from abc import ABC, abstractmethod
from typing import Generic

from int3.registers import Registers, Immediate, IntImmediate

from .emitter import Emitter


class ArchitectureEmitter(Emitter, ABC, Generic[Registers]):
    @abstractmethod
    def mov(self, dst: Registers, src: Registers):
        ...

    @abstractmethod
    def load(self, dst: Registers, src_ptr: Registers, offset: int = 0):
        ...

    @abstractmethod
    def clear(self, reg: Registers):
        ...

    @abstractmethod
    def push(self, value: Registers | Immediate):
        ...

    @abstractmethod
    def pop(self, result: Registers | None = None) -> Registers:
        ...

    @abstractmethod
    def add(self, dst: Registers, operand: Registers | IntImmediate):
        ...

    @abstractmethod
    def sub(self, dst: Registers, operand: Registers | IntImmediate):
        ...

    @abstractmethod
    def xor(self, dst: Registers, operand: Registers | IntImmediate):
        ...

    @abstractmethod
    def neg(self, dst: Registers):
        ...

    @abstractmethod
    def call(self, target: Registers):
        ...
