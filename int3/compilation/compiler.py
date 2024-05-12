from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterator

from int3.architectures import ArchitectureMeta, ArchitectureMetas
from int3.ir import IrAbstractPredicate, IrBasicBlock
from int3.strategy import Strategy

from .compiler_scope import CompilerScope


@dataclass
class Compiler:
    arch: str

    strategy: Strategy = Strategy.CodeSize
    bad_bytes: bytes = b""

    active_bb_stack: list[IrBasicBlock] = field(init=False, default_factory=list)

    entry_bb: IrBasicBlock = field(init=False)
    arch_meta: ArchitectureMeta = field(init=False)

    def __post_init__(self):
        self.arch_meta = ArchitectureMetas.from_str(self.arch)

        self.entry_bb = self.spawn_bb()
        self.active_bb_stack.append(self.entry_bb)

    def compile(self) -> str:
        # XXX
        return "work-in-progress"

    @contextmanager
    def active_bb_cm(self, bb: IrBasicBlock) -> Iterator[IrBasicBlock]:
        try:
            self.active_bb_stack.append(bb)
            yield bb
        finally:
            self.active_bb_stack.pop()

    @property
    def active_bb(self) -> IrBasicBlock:
        return self.active_bb_stack[-1]

    @property
    def active_scope(self) -> CompilerScope:
        return self.active_bb.cc_scope

    def spawn_bb(self, new_scope: bool = False) -> IrBasicBlock:
        cc_scope = self.spawn_scope() if new_scope else self.active_scope
        return IrBasicBlock(cc_scope=cc_scope)

    def spawn_scope(self) -> CompilerScope:
        # TODO
        return CompilerScope(cc=self, local_vars=[], global_vars=[])

    @contextmanager
    def if_else(
        self, predicate: IrAbstractPredicate
    ) -> Iterator[tuple[IrBasicBlock, IrBasicBlock]]:
        # TODO: Handle the predicate and emit branches based on the result.

        if_bb = self.spawn_bb(new_scope=True)
        else_bb = self.spawn_bb(new_scope=True)

        yield if_bb, else_bb

        next_bb = self.spawn_bb()
        self.active_bb_stack.append(next_bb)
