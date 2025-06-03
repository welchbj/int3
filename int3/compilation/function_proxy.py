from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from types import TracebackType
from typing import TYPE_CHECKING, ContextManager, cast

from llvmlite import ir as llvmir

from int3.errors import Int3CompilationError

from .types import IntType, IntValueType, IntVariable, ReturnType, VoidType

if TYPE_CHECKING:
    from .compiler import Compiler


@dataclass
class FunctionProxy:
    """Wrapper around an LLVM IR function."""

    compiler: "Compiler"
    name: str
    return_type: ReturnType
    arg_types: list[IntType] = field(default_factory=list)
    args: list[IntVariable] = field(init=False)

    name_counter: Counter = field(init=False, default_factory=Counter)
    llvm_func: llvmir.Function = field(init=False)
    llvm_func_type: llvmir.FunctionType = field(init=False)
    llvm_entry_block: llvmir.Block = field(init=False)
    llvm_builder: llvmir.IRBuilder = field(init=False)

    # Internal context manager used to manage shared lifetimes between function
    # and compiler utilities.
    _current_function_cm: ContextManager[FunctionProxy] | None = field(
        init=False, default=None
    )

    def __post_init__(self):
        self.llvm_func_type = llvmir.FunctionType(
            return_type=self.return_type.wrapped_type,
            args=[arg.wrapped_type for arg in self.arg_types],
        )
        self.llvm_func = llvmir.Function(
            module=self.compiler.llvm_module,
            ftype=self.llvm_func_type,
            name=self.name,
        )

        self.args = []
        for idx, arg_type in enumerate(self.arg_types):
            self.args.append(
                IntVariable(
                    compiler=self.compiler,
                    type=arg_type,
                    wrapped_llvm_node=self.llvm_func.args[idx],
                )
            )

        self.llvm_entry_block = self.llvm_func.append_basic_block(name="entry")
        self.llvm_builder = llvmir.IRBuilder(self.llvm_entry_block)

    @property
    def current_block(self) -> llvmir.Block:
        return self.llvm_builder.block

    def make_name(self, hint: str | None = None) -> str:
        if hint is None:
            hint = "var"

        self.name_counter.update((hint,))
        idx = self.name_counter[hint]
        return f"{hint}{idx}"

    def __call__(self, *args: IntValueType) -> IntVariable | None:
        llvm_ret_value = self.compiler.current_func.llvm_builder.call(
            fn=self.llvm_func,
            args=[arg.wrapped_llvm_node for arg in args],
        )

        if self.return_type == self.compiler.types.void:
            return None
        else:
            return_type = cast(IntType, self.return_type)

        return IntVariable(
            compiler=self.compiler, type=return_type, wrapped_llvm_node=llvm_ret_value
        )

    def __enter__(self) -> FunctionProxy:
        self._current_function_cm = self.compiler._current_function_as(self)
        return self._current_function_cm.__enter__()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self._current_function_cm is None:
            raise RuntimeError("This should be unreachable!")
        elif exc_type is not None:
            # An exception is already bubbling up, let's not further inspect
            # the state of this function.
            pass
        else:
            if not self.current_block.is_terminated:
                if self.return_type == self.compiler.types.void:
                    # Add an implicit void return.
                    self.llvm_builder.ret_void()
                else:
                    # No return specified despite a non-void return type.
                    raise Int3CompilationError(
                        f"No return specified in {self.name} despite non-void return "
                        f"type {self.return_type}"
                    )

            self._current_function_cm.__exit__(None, None, None)
            self._current_function_cm = None


@dataclass
class PartialFunctionDef:
    name: str

    factory: FunctionFactory

    def __call__(
        self,
        return_type: IntType | VoidType | type[int] | None = None,
        *arg_types: IntType | type[int],
    ) -> FunctionProxy:
        compiler = self.factory.compiler

        if return_type is None:
            return_type = compiler.types.void
        elif isinstance(return_type, (VoidType, IntType)):
            # Leave as is.
            pass
        else:
            # Promote the literal type[int] to the target's native integer.
            return_type = compiler.types.inat

        new_func = FunctionProxy(
            compiler=self.factory.compiler,
            name=self.name,
            return_type=return_type,
            arg_types=[
                arg if isinstance(arg, IntType) else compiler.types.inat
                for arg in arg_types
            ],
        )
        self.factory.func_map[self.name] = new_func
        return new_func


@dataclass
class FunctionFactory:
    compiler: "Compiler"

    func_map: dict[str, FunctionProxy] = field(init=False, default_factory=dict)

    def __getattr__(self, attr: str) -> PartialFunctionDef | FunctionProxy:
        func_proxy = self.func_map.get(attr, None)
        if func_proxy is None:
            # We're defining a new function.
            return PartialFunctionDef(name=attr, factory=self)
        else:
            # We're accessing a function that was already defined.
            return func_proxy
