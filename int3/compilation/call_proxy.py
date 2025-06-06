from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from llvmlite import ir as llvmir

from int3.errors import Int3CompilationError

from .types import IntType, IntVariable, PyIntValueType

if TYPE_CHECKING:
    from .compiler import Compiler
    from .function_proxy import FunctionProxy


@dataclass
class CallProxy:
    func: "FunctionProxy"

    def __call__(self, *args: PyIntValueType) -> IntVariable | None:
        func = self.func
        compiler = func.compiler
        symtab_ptr = compiler.current_func.args[0].wrapped_llvm_node

        func_args = [symtab_ptr]
        func_args.extend([arg.wrapped_llvm_node for arg in args])

        # Emit stub to resolve the pointer of the function we want to call.
        symtab_idx = compiler.i32(func.symtab_index).wrapped_llvm_node
        func_ptr = compiler.builder.gep(
            ptr=symtab_ptr,
            indices=[symtab_idx],
            source_etype=compiler.types.ptr.wrapped_type,
        )

        # This is a bad hack to trick llvmlite into generating LLVM IR that
        # calls our function pointer rather than a defined function.
        #
        # XXX: Consider submitting a patch to llvmlite to change the call() API.
        class _fake_func:
            def get_reference(self) -> str:
                return f'{func_ptr.name_prefix}"{func_ptr.name}"'

            @property
            def function_type(self) -> llvmir.FunctionType:
                return func.llvm_func.function_type

        # Emit the call to the resolved function pointer.
        call_instr = compiler.current_func.llvm_builder.call(
            fn=_fake_func(),
            args=func_args,
        )

        if func.return_type == compiler.types.void:
            return None
        elif func.return_type == compiler.types.ptr:
            raise NotImplementedError("Pointer return types not yet implemented")
        else:
            return_type = cast(IntType, func.return_type)

        return IntVariable(
            compiler=compiler, type=return_type, wrapped_llvm_node=call_instr
        )


@dataclass
class CallFactory:
    compiler: "Compiler"

    def __getattr__(self, attr: str) -> CallProxy:
        func_proxy = self.compiler.func.func_map.get(attr, None)
        if func_proxy is None:
            raise Int3CompilationError(f"No defined function: {attr}")

        return CallProxy(func=func_proxy)
