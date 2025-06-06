from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

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

        # Emit stub to resolve the pointer of the function we want to
        # call.
        # TODO

        # Emit the call to the resolved function pointer.
        # TODO
        llvm_ret_value = compiler.current_func.llvm_builder.call(
            fn=func.llvm_func,
            args=[arg.wrapped_llvm_node for arg in args],
        )

        if func.return_type == compiler.types.void:
            return None
        elif func.return_type == compiler.types.ptr:
            raise NotImplementedError("Pointer return types not yet implemented")
        else:
            return_type = cast(IntType, func.return_type)

        return IntVariable(
            compiler=compiler, type=return_type, wrapped_llvm_node=llvm_ret_value
        )


@dataclass
class CallFactory:
    compiler: "Compiler"

    def __getattr__(self, attr: str) -> CallProxy:
        func_proxy = self.compiler.func.func_map.get(attr, None)
        if func_proxy is None:
            raise Int3CompilationError(f"No defined function: {attr}")

        return CallProxy(func=func_proxy)
