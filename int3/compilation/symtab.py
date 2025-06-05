from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from llvmlite import ir as llvmir

if TYPE_CHECKING:
    from .compiler import Compiler


@dataclass
class SymbolTable:
    """Implementation of basic table for runtime resolution of symbols.

    Only one SymbolTable instance should be created for a given Compiler.

    """

    compiler: "Compiler"

    entry_slot_map: dict[str, int] = field(init=False, default_factory=dict)
    entry_stub_name: str = "entry_stub"
    wrapped_struct: llvmir.LiteralStructType = field(init=False)

    def __post_init__(self):
        # Setup our lookup table of symbol names to indexes.
        idx = 0
        for func_name, func in self.compiler.func.func_map.items():
            if func_name == self.entry_stub_name:
                continue

            self.entry_slot_map[func_name] = idx
            idx += 1

        # Define our wrapped LLVM struct.
        ctx = self.compiler.llvm_module.context
        symtab_struct = ctx.get_identified_type("struct.symtab", packed=False)
        symtab_struct.set_body(
            *[llvmir.PointerType() for _ in range(len(self.entry_slot_map))]
        )
        self.wrapped_struct = symtab_struct

    def func_slot_ptr(
        self, struct_ptr: llvmir.PointerType, func_name: str
    ) -> llvmir.Instruction:
        def _make_gep_idx(value: int) -> llvmir.Constant:
            return self.compiler.i32(value).wrapped_llvm_node

        # llvmlite gep examples:
        # https://github.com/numba/llvmlite/issues/442#issuecomment-459690710
        idx = self.entry_slot_map[func_name]
        indices = [_make_gep_idx(0), _make_gep_idx(idx)]
        return self.compiler.builder.gep(struct_ptr, indices=indices, inbounds=True)

    def alloc(self) -> llvmir.Instruction:
        """Allocate and setup within the compiler's current function."""
        return self.compiler.builder.alloca(typ=self.wrapped_struct)
