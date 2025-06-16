from __future__ import annotations

import random
import string
from collections import Counter
from dataclasses import dataclass, field
from types import TracebackType
from typing import TYPE_CHECKING, ContextManager, cast

from int3._vendored.llvmlite import ir as llvmir
from int3.errors import Int3CompilationError, Int3ProgramDefinitionError

from .types import (
    IntType,
    IntVariable,
    IrArgType,
    IrReturnType,
    Pointer,
    PointerType,
    VoidType,
)

if TYPE_CHECKING:
    from .compiler import Compiler


def _make_prefix_marker() -> str:
    return "".join(random.choice(string.ascii_letters) for _ in range(8))


@dataclass
class FunctionProxy:
    """Wrapper around an LLVM IR function."""

    compiler: "Compiler"
    name: str
    return_type: IrReturnType

    # These argument type and value lists always begin with the implicit
    # symtab pointer argument.
    arg_types: list[IrArgType] = field(default_factory=list)
    args: list[IntVariable | Pointer] = field(init=False)

    prefix_marker: str = field(init=False, default_factory=_make_prefix_marker)
    name_counter: Counter = field(init=False, default_factory=Counter)
    symtab_index: int = field(init=False)
    llvm_func_type: llvmir.FunctionType = field(init=False)
    llvm_func: llvmir.Function = field(init=False)
    llvm_entry_block: llvmir.Block = field(init=False)
    llvm_builder: llvmir.IRBuilder = field(init=False)

    # Internal context manager used to manage shared lifetimes between function
    # and compiler utilities.
    _current_function_cm: ContextManager[FunctionProxy] | None = field(
        init=False, default=None
    )

    @property
    def raw_symtab_ptr(self) -> llvmir.Instruction:
        return cast(llvmir.Instruction, self.args[0].wrapped_llvm_node)

    @property
    def user_arg_view(self) -> list[IntVariable | Pointer]:
        """View into the user's function arguments (omitting the implicit symtab pointer)."""
        return self.args[1:]

    def __post_init__(self):
        self.symtab_index = self.compiler.reserve_symbol_index()

        self.llvm_func_type = llvmir.FunctionType(
            return_type=self.return_type.wrapped_type,
            args=[arg_type.wrapped_type for arg_type in self.arg_types],
        )
        self.llvm_func = llvmir.Function(
            module=self.compiler.llvm_module,
            ftype=self.llvm_func_type,
            name=self.name,
        )

        self.args = []
        for idx, arg_type in enumerate(self.arg_types):
            llvm_arg = cast(llvmir.Instruction, self.llvm_func.args[idx])

            if isinstance(arg_type, IntType):
                self.args.append(
                    IntVariable(
                        compiler=self.compiler,
                        type=arg_type,
                        wrapped_llvm_node=llvm_arg,
                    )
                )
            else:
                # Assume PointerType.
                self.args.append(
                    Pointer(
                        compiler=self.compiler,
                        type=arg_type,
                        wrapped_llvm_node=llvm_arg,
                    )
                )

        self.llvm_entry_block = self.llvm_func.append_basic_block(name="entry")
        self.llvm_builder = llvmir.IRBuilder(self.llvm_entry_block)

    @property
    def current_block(self) -> llvmir.Block:
        return cast(llvmir.Block, self.llvm_builder.block)

    def make_name(self, hint: str | None = None) -> str:
        if hint is None:
            hint = "var"

        self.name_counter.update((hint,))
        idx = self.name_counter[hint]
        return f"{hint}{idx}"

    def __str__(self) -> str:
        # TODO: Show full signature
        return f"func {self.name}"

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

    store: FunctionStore

    def __call__(
        self,
        # TODO: These need to reflect realness
        return_type: IntType | VoidType | type[int] | None = None,
        *arg_types: IrArgType | type[int] | type[bytes],
    ) -> FunctionProxy:
        compiler = self.store.compiler

        # Promote the return type
        promoted_return_type: IrReturnType
        if return_type is None:
            promoted_return_type = compiler.types.void
        elif isinstance(return_type, (VoidType, IntType, PointerType)):
            # Leave as is.
            promoted_return_type = return_type
        else:
            # Promote the literal type[int] to the target's native integer.
            promoted_return_type = compiler.types.inat

        # The first argument type is the implicit pointer to the symtab struct.
        promoted_arg_types: list[IrArgType]
        promoted_arg_types = [compiler.types.ptr]

        # Promote all user-specified argument types.
        for arg_type in arg_types:
            if isinstance(arg_type, (IntType, PointerType)):
                promoted_arg_types.append(arg_type)
            elif arg_type == int:
                promoted_arg_types.append(compiler.types.inat)
            elif arg_type == bytes:
                promoted_arg_types.append(compiler.types.ptr)
            else:
                raise Int3ProgramDefinitionError(
                    f"Unexpected argument type: {arg_type}"
                )

        new_func = FunctionProxy(
            compiler=self.store.compiler,
            name=self.name,
            return_type=promoted_return_type,
            arg_types=promoted_arg_types,
        )
        self.store.func_map[self.name] = new_func
        return new_func


@dataclass
class FunctionFactory:
    store: "FunctionStore"

    def __getattr__(self, attr: str) -> PartialFunctionDef:
        func_proxy = self.store.func_map.get(attr, None)
        if func_proxy is not None:
            raise Int3ProgramDefinitionError(f"Attempted to re-define function {attr}")

        # We're defining a new function.
        return PartialFunctionDef(name=attr, store=self.store)


@dataclass
class FunctionStore:
    compiler: "Compiler"

    func_map: dict[str, FunctionProxy] = field(init=False, default_factory=dict)

    def __getattr__(self, attr: str) -> FunctionProxy:
        func_proxy = self.func_map.get(attr, None)
        if func_proxy is None:
            raise Int3ProgramDefinitionError(
                f"Attempted to access undefined function: {attr}"
            )

        return func_proxy
