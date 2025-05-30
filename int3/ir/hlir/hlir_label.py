from dataclasses import dataclass

from int3._interfaces import PrintableIr


@dataclass(frozen=True)
class HlirLabel(PrintableIr):
    name: str

    def to_str(self, indent: int = 0) -> str:
        indent_str = self.indent_str(indent)
        return f"{indent_str}{self.name}"
