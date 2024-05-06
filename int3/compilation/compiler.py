from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import ContextManager, Iterator

from int3.architectures import ArchitectureMeta, ArchitectureMetas
from int3.ir import IrAbstractPredicate, IrBasicBlock
from int3.strategy import Strategy


@dataclass
class Compiler:
    arch: str

    strategy: Strategy = Strategy.CodeSize
    bad_bytes: bytes = b""

    # TODO: current_basic_block?

    basic_blocks: list[IrBasicBlock] = field(init=False, default_factory=list)
    arch_meta: ArchitectureMeta = field(init=False)

    def __post_init__(self):
        self.arch_meta = ArchitectureMetas.from_str(self.arch)

    def compile(self) -> str:
        # XXX
        print(self.basic_blocks)

    @contextmanager
    def if_else(
        self, predicate: IrAbstractPredicate
    ) -> Iterator[tuple[ContextManager, ContextManager]]:
        # TODO: How do we define the "scope" of a bb?
        #       What's the compiler's relationship with a bb?

        if_bb = IrBasicBlock()
        # TODO

        else_bb = IrBasicBlock()
        # TODO

        yield if_bb, else_bb

        next_bb = IrBasicBlock()
        # TODO
