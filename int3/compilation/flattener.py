from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from int3._interfaces import PrintableIr
from int3.architecture import Architecture
from int3.ir import HlirBranch, HlirOperation, LlirOperation, LlirOperator

if TYPE_CHECKING:
    from int3.compilation import Block, Compiler, Function


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class FlattenedProgram(PrintableIr):
    functions: tuple[FlattenedFunction, ...]

    def to_str(self, indent: int = 0) -> str:
        indent_str = self.indent_str(indent)
        return f"\n{indent_str}".join(str(func) for func in self.functions)


@dataclass(frozen=True)
class FlattenedFunction(PrintableIr):
    name: str
    ops: tuple[LlirOperation, ...]

    def add_operation(self, op: LlirOperation): ...

    @staticmethod
    def from_func(func: "Function") -> FlattenedFunction:
        llir_ops: list[LlirOperation] = []

        for block in func.blocks:
            # TODO
            pass

        return FlattenedFunction(name=func.name, ops=tuple(llir_ops))

    def to_str(self, indent: int = 0) -> str:
        indent_str = self.indent_str(indent)

        text = f"{indent_str}func {self.name}:\n"
        for op in self.ops:
            text += op.to_str(indent=indent + 1)

        return text


@dataclass
class Flattener:
    compiler: "Compiler"

    def flatten(self) -> FlattenedProgram:
        flattened_functions: list[FlattenedFunction] = []

        for func_name, func in self.compiler.func.func_map.items():
            logger.debug(f"Performing function flatten on {func_name}...")
            flattened_functions.append(FlattenedFunction.from_func(func))

        return FlattenedProgram(functions=tuple(flattened_functions))
