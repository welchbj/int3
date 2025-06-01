from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from types import TracebackType
from typing import TYPE_CHECKING, ContextManager

from llvmlite import ir as llvmir

if TYPE_CHECKING:
    from .compiler import Compiler


@dataclass
class FunctionProxy:
    """Wrapper around an LLVM IR function."""

    compiler: "Compiler"
    name: str
    llvm_func_type: llvmir.FunctionType

    llvm_func: llvmir.Function = field(init=False)
    llvm_entry_block: llvmir.Block = field(init=False)
    llvm_builder: llvmir.IRBuilder = field(init=False)
    name_counter: Counter = field(init=False, default_factory=Counter)

    # Internal context manager used to manage shared lifetimes between function
    # and compiler utilities.
    _current_function_cm: ContextManager[FunctionProxy] | None = field(
        init=False, default=None
    )

    def __post_init__(self):
        self.llvm_func = llvmir.Function(
            module=self.compiler.llvm_module,
            ftype=self.llvm_func_type,
            name=self.name,
        )
        self.llvm_entry_block = self.llvm_func.append_basic_block(name="entry")
        self.llvm_builder = llvmir.IRBuilder(self.llvm_entry_block)

    def make_name(self, hint: str | None = None) -> str:
        if hint is None:
            hint = "var"

        self.name_counter.update((hint,))
        idx = self.name_counter[hint]
        return f"{hint}{idx}"

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
        else:
            if (
                self.llvm_func_type.return_type == self.compiler.types.void
                and not self.llvm_builder.block.is_terminated
            ):
                # Add an implicit void return.
                self.llvm_builder.ret_void()

            self._current_function_cm.__exit__(None, None, None)
            self._current_function_cm = None


@dataclass
class PartialFunctionDef:
    name: str

    factory: FunctionFactory

    def __call__(
        self, func_type: llvmir.FunctionType | None = None
    ) -> FunctionProxy:
        if func_type is None:
            func_type = llvmir.FunctionType(
                return_type=self.factory.compiler.types.void, args=[]
            )

        new_func = FunctionProxy(
            compiler=self.factory.compiler,
            name=self.name,
            llvm_func_type=func_type,
        )
        self.factory.func_map[self.name] = new_func
        return new_func


@dataclass
class FunctionFactory:
    compiler: "Compiler"

    func_map: dict[str, FunctionProxy] = field(init=False, default_factory=dict)

    def __getattr__(self, attr: str) -> PartialFunctionDef:
        return PartialFunctionDef(name=attr, factory=self)
