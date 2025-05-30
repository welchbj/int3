from dataclasses import dataclass

from int3._interfaces import PrintableIr


@dataclass(frozen=True)
class LlirConstant(PrintableIr):
    signed: bool
    bit_size: int
    value: int

    @property
    def type_str(self) -> str:
        signedness = "i" if self.signed else "u"
        return f"{signedness}{self.bit_size}"

    def to_str(self, indent: int = 0) -> str:
        indent_str = self.indent_str(indent)
        return f"{indent_str}{self.value:#x}/{self.type_str}"
