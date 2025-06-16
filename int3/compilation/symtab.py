import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

from int3._vendored.llvmlite import ir as llvmir

if TYPE_CHECKING:
    from .compiler import Compiler
    from .function_proxy import FunctionStore


logger = logging.getLogger(__name__)


@dataclass
class SymbolTable:
    """Implementation of basic table for runtime resolution of symbols.

    Only one SymbolTable instance should be created for a given Compiler.

    """

    # We don't load funcs or the number of slots implicitly from the
    # compiler due to the nuances of the entry stub generation, where
    # we spawn a sub-compiler that needs to reference the top-level
    # compiler's function definitions.
    funcs: "FunctionStore"
    num_slots: int
    compiler: "Compiler"

    wrapped_struct: llvmir.LiteralStructType = field(init=False)

    def __post_init__(self):
        # Record the number of slots the compiler has given out.
        logger.debug(f"Setting up symbol table with {self.num_slots} slots")

        # Define our wrapped LLVM struct.
        ctx = self.compiler.llvm_module.context
        symtab_struct = ctx.get_identified_type("struct.symtab", packed=False)
        symtab_struct.set_body(*[llvmir.PointerType() for _ in range(self.num_slots)])
        self.wrapped_struct = symtab_struct

    def _make_gep_idx(self, value: int) -> llvmir.Constant:
        return cast(llvmir.Constant, self.compiler.i32(value).wrapped_llvm_node)

    def slot_ptr(self, struct_ptr: llvmir.PointerType, idx: int) -> llvmir.Instruction:
        indices = [self._make_gep_idx(idx)]

        # llvmlite gep examples:
        # https://github.com/numba/llvmlite/issues/442#issuecomment-459690710
        gep_instr = self.compiler.builder.gep(
            struct_ptr,
            indices=indices,
            inbounds=True,
            source_etype=self.compiler.types.ptr.wrapped_type,
        )
        return cast(llvmir.Instruction, gep_instr)

    def alloc(self) -> llvmir.Instruction:
        """Allocate and setup within the compiler's current function."""
        return cast(
            llvmir.Instruction, self.compiler.builder.alloca(typ=self.wrapped_struct)
        )
