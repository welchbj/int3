from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING

from int3._interfaces import PrintableIr

from .hlir_label import HlirLabel

if TYPE_CHECKING:
    from .hlir_variable import HlirAnyType


class HlirBranchOperator(Enum):
    LessThan = auto()
    # TODO


@dataclass
class HlirBranch(PrintableIr):
    operator: HlirBranchOperator
    args: list["HlirAnyType"]

    if_target: HlirLabel | None = None
    else_target: HlirLabel | None = None

    def set_targets(self, if_target: HlirLabel, else_target: HlirLabel):
        self.if_target = if_target
        self.else_target = else_target

    def to_str(self, indent: int = 0) -> str:
        outer_indent_str = self.indent_str(indent)
        inner_indent_str = self.indent_str(indent + 1)

        text = f"{outer_indent_str}branch {self.operator.name}"
        text += "("
        text += ", ".join(str(arg) for arg in self.args)
        text += ")\n"
        text += f"{inner_indent_str}then {self.if_target}\n"
        text += f"{inner_indent_str}else {self.else_target}"
        return text
