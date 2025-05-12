import random
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterator

from int3.architecture import Architecture
from int3.codegen import CodeGenerator
from int3.ir import Block, Constant, Label, Predicate, Variable


@dataclass
class Compiler:
    # TODO: Platform that is combination of arch, calling convention, syscalls, etc.
    arch: Architecture

    code_generator: CodeGenerator = field(init=False)
    used_labels: set[str] = field(init=False, default_factory=set)

    def make_label(self, hint: str) -> str:
        """Generate a unique label."""
        while True:
            rand_str = "".join(random.choice("0123456789abcdef") for _ in range(4))
            maybe_label = f"{hint}_{rand_str}"

            if maybe_label in self.used_labels:
                continue

            self.used_labels.add(maybe_label)
            return maybe_label

    @contextmanager
    def if_else(self, predicate: Predicate) -> Iterator[tuple[Block, Block]]: ...

    @contextmanager
    def try_finally(self) -> Iterator[tuple[Block, Block]]: ...

    def mov(self, dest: Variable, src: Variable | Constant): ...

    def add(self, dest: Variable, one: Variable, two: Variable | Constant): ...

    def xor(self, dest: Variable, one: Variable, two: Variable | Constant): ...

    def sub(self, dest: Variable, one: Variable, two: Variable | Constant): ...

    def call(self, target: Label): ...
