from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from int3._vendored.llvmlite import ir as llvmir
from int3.errors import Int3CompilationError

from .types import IntType, IntVariable, PointerType, PyArgType

if TYPE_CHECKING:
    from .compiler import Compiler
    from .function_proxy import FunctionProxy


@dataclass
class CallProxy:
    func: "FunctionProxy"

    def __call__(self, *args: PyArgType) -> IntVariable | None:
        compiler = self.func.compiler
        symtab_ptr = compiler.current_func.raw_symtab_ptr
        return self.call_func(
            func=self.func,
            compiler=compiler,
            symtab_ptr=symtab_ptr,
            args=args,
        )

    @staticmethod
    def call_func(
        func: "FunctionProxy",
        compiler: "Compiler",
        symtab_ptr: llvmir.Instruction,
        args: tuple[PyArgType, ...],
    ) -> IntVariable | None:
        """Worker method for setting up LLVM IR to call a relocated function.

        func, compiler, and symtab_ptr are split up as different arguments to
        give us the flexibility of generating calls to one compiler's symtab
        from a different compiler (like we do in the entry stub).

        """
        # Add the implicit symtab pointer into the function call.
        func_args = [symtab_ptr]

        # Construct arg list of LLVM nodes, promoting raw types along the way.
        for arg_index, user_arg in enumerate(args):
            target_type = func.arg_types[arg_index]

            if isinstance(user_arg, int):
                if not isinstance(target_type, IntType):
                    raise Int3CompilationError(
                        f"Passed raw integer for non-int argument type {target_type}"
                    )
                coerced_var = compiler.coerce_to_type(user_arg, target_type)
                llvm_node = coerced_var.wrapped_llvm_node
            elif isinstance(user_arg, bytes):
                if not isinstance(target_type, PointerType):
                    raise Int3CompilationError(
                        f"Passed raw bytes for non-pointer argument type {target_type}"
                    )

                llvm_node = compiler.b(user_arg).wrapped_llvm_node
            else:
                llvm_node = user_arg.wrapped_llvm_node

            func_args.append(cast(llvmir.Instruction, llvm_node))

        # Emit stub to resolve the pointer of the function we want to call.
        def _make_gep_idx(value: int) -> llvmir.Constant:
            return cast(llvmir.Constant, compiler.i32(value).wrapped_llvm_node)

        indices = [_make_gep_idx(func.symtab_index)]
        func_ptr_ptr = compiler.builder.gep(
            ptr=symtab_ptr,
            indices=indices,
            source_etype=compiler.types.ptr.wrapped_type,
        )
        func_ptr = compiler.builder.load(
            func_ptr_ptr, typ=compiler.types.ptr.wrapped_type
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
                return cast(llvmir.FunctionType, func.llvm_func.function_type)

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
