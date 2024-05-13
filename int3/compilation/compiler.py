from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterator

from int3.architectures import ArchitectureMeta, ArchitectureMetas
from int3.ir import IrAbstractBranch, IrAbstractPredicate, IrBasicBlock
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

        self.entry_bb = IrBasicBlock(cc_scope=CompilerScope(cc=self))
        self.active_bb_stack.append(self.entry_bb)

    def compile_ir(self) -> str:
        return str(self.entry_bb)

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

    def spawn_bb(
        self,
        new_scope: bool = False,
        set_as_active: bool = False,
    ) -> IrBasicBlock:
        cc_scope = self.spawn_scope() if new_scope else self.active_scope
        bb = IrBasicBlock(cc_scope=cc_scope)

        if set_as_active:
            self.active_bb_stack.append(bb)

        return bb

    def spawn_scope(
        self, inherit_locals: bool = True, inherit_globals: bool = True
    ) -> CompilerScope:
        return self.active_scope.clone(
            inherit_locals=inherit_locals, inherit_globals=inherit_globals
        )

    @contextmanager
    def if_else(
        self, predicate: IrAbstractPredicate
    ) -> Iterator[tuple[IrBasicBlock, IrBasicBlock]]:
        if_bb = self.spawn_bb(new_scope=True)
        if_bb.add_incoming_edge(self.active_bb)

        else_bb = self.spawn_bb(new_scope=True)
        else_bb.add_incoming_edge(self.active_bb)

        self.active_bb.add_operation(predicate)
        self.active_bb.add_operation(IrAbstractBranch(taken=if_bb, not_taken=else_bb))

        next_bb = self.spawn_bb(set_as_active=True)
        if_bb.add_outgoing_edge(next_bb)
        else_bb.add_outgoing_edge(next_bb)

        yield if_bb, else_bb
