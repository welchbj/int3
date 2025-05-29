from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from types import TracebackType
from typing import TYPE_CHECKING, ContextManager, Iterator

from int3._interfaces import PrintableIr

from .block import Block
from .scope import Scope

if TYPE_CHECKING:
    from .compiler import Compiler


_ENTRY_LABEL_NAME = "entry"


@dataclass
class Function(PrintableIr):
    compiler: "Compiler"
    name: str

    # Entrypoint block for this function.
    entry: Block = field(init=False)

    # The stack used to maintain the concept of the function's "current" block.
    block_stack: list[Block] = field(init=False)

    # All blocks contained within this function.
    blocks: list[Block] = field(init=False, default_factory=list)

    # Internal context manager used to manage shared lifetimes between function
    # and compiler utilities.
    _current_function_cm: ContextManager[Function] | None = field(
        init=False, default=None
    )

    def __post_init__(self):
        self.entry = Block(
            compiler=self.compiler, scope_stack=[Scope()], label=_ENTRY_LABEL_NAME
        )
        self.blocks = [self.entry]
        self.block_stack = [self.entry]

    @property
    def current_block(self) -> Block:
        """The IR block the compiler/function is currently operating on.

        Most user-facing compiler operations will implicitly modify the block
        this property references.

        """
        return self.block_stack[-1]

    def to_str(self, indent: int = 0) -> str:
        indent_str = self.indent_str(indent)

        text = f"{indent_str}func {self.name}:\n"
        for block in self.blocks:
            text += block.to_str(indent=indent + 1)

        return text

    def _spawn_block(
        self,
        inherit_scope: bool = True,
        base_block: Block | None = None,
        name_hint: str | None = None,
    ) -> Block:
        if name_hint is None:
            name_hint = "block"

        if base_block is None:
            base_block = self.current_block

        if inherit_scope:
            scope_stack = list(base_block.scope_stack)
        else:
            scope_stack = []

        scope_stack.append(Scope())
        new_label = self.compiler._make_unique_label(name_hint)
        new_block = Block(
            compiler=self.compiler, scope_stack=scope_stack, label=new_label
        )
        self.compiler.label_map[new_label] = new_block
        self.blocks.append(new_block)

        return new_block

    @contextmanager
    def _current_block_as(self, block: Block) -> Iterator[Block]:
        """Context manager to set the compiler's current block."""
        self.block_stack.append(block)

        try:
            yield block
        finally:
            self.block_stack.pop()

    def __enter__(self) -> Function:
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
            self._current_function_cm.__exit__(None, None, None)
            self._current_function_cm = None


@dataclass
class PartialFunctionDef:
    name: str

    factory: FunctionFactory

    def __call__(self) -> Function:
        new_func = Function(compiler=self.factory.compiler, name=self.name)
        self.factory.func_map[self.name] = new_func
        return new_func


@dataclass
class FunctionFactory:
    compiler: "Compiler"

    func_map: dict[str, Function] = field(init=False, default_factory=dict)

    def __getattr__(self, attr: str) -> PartialFunctionDef:
        return PartialFunctionDef(name=attr, factory=self)
