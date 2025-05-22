from dataclasses import dataclass

from int3._interfaces import PrintableIr


@dataclass
class IrJump(PrintableIr):
    def to_str(self, indent=0):
        indent_str = self.indent_str(indent)
        return f"{indent_str}jump TODO"
