import random
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterator, Literal

from int3.architectures import ArchitectureMeta, ArchitectureMetas
from int3.errors import Int3MissingEntityError
from int3.ir import (
    IrAbstractBranch,
    IrAbstractPredicate,
    IrBasicBlock,
    IrBytesConstant,
    IrBytesType,
    IrGlobalVar,
    IrIntConstant,
    IrIntType,
    IrLocalVar,
    IrVar,
)
from int3.strategy import Strategy

from .compiler_scope import CompilerScope


@dataclass
class Compiler:
    arch: str

    strategy: Strategy = Strategy.CodeSize
    bad_bytes: bytes = b""

    active_bb_stack: list[IrBasicBlock] = field(init=False, default_factory=list)
    used_labels: set[str] = field(init=False, default_factory=set)

    entry_bb: IrBasicBlock = field(init=False)
    arch_meta: ArchitectureMeta = field(init=False)

    def __post_init__(self):
        self.arch_meta = ArchitectureMetas.from_str(self.arch)

        self.entry_bb = IrBasicBlock(label="entry", cc_scope=CompilerScope(cc=self))
        self.used_labels.add("entry")
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

    def as_int_constant(self, value: int, signed: bool = False) -> IrIntConstant:
        match bit_size := self.arch_meta.bit_size:
            case 32:
                return IrIntConstant.i32(value) if signed else IrIntConstant.u32(value)
            case 64:
                return IrIntConstant.i64(value) if signed else IrIntConstant.u64(value)
            case _:
                raise Int3MissingEntityError(f"Unexpected bit size {bit_size}")

    def make_native_int_var(
        self, signed: bool = False, scope: Literal["local", "global"] = "local"
    ) -> IrVar:
        match bit_size := self.arch_meta.bit_size:
            case 32:
                type_ = IrIntType.i32() if signed else IrIntType.u32()
            case 64:
                type_ = IrIntType.i64() if signed else IrIntType.u64()
            case _:
                raise Int3MissingEntityError(f"Unexpected bit size {bit_size}")

        name = self.active_scope.make_var_name(prefix=scope)
        if scope == "local":
            return IrLocalVar(name=name, type_=type_)
        else:
            return IrGlobalVar(name=name, type_=type_)

    def as_bytes_constant(self, value: bytes) -> IrBytesConstant:
        return IrBytesConstant(type_=IrBytesType(), value=value)

    def make_label(self, hint: str) -> str:
        """Generate a unique label."""
        while True:
            rand_str = "".join(random.choice("0123456789abcdef") for _ in range(4))
            maybe_label = f"{hint}_{rand_str}"

            if maybe_label in self.used_labels:
                continue

            self.used_labels.add(maybe_label)
            return maybe_label

    def spawn_bb(
        self,
        new_scope: bool = False,
        set_as_active: bool = False,
        label_hint: str | None = None,
    ) -> IrBasicBlock:
        label_hint = "bb" if label_hint is None else label_hint
        label = self.make_label(label_hint)

        cc_scope = self.spawn_scope() if new_scope else self.active_scope
        bb = IrBasicBlock(label=label, cc_scope=cc_scope)

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
        if_bb = self.spawn_bb(new_scope=True, label_hint="then")
        if_bb.add_incoming_edge(self.active_bb)

        else_bb = self.spawn_bb(new_scope=True, label_hint="otherwise")
        else_bb.add_incoming_edge(self.active_bb)

        self.active_bb.add_operation(predicate)
        self.active_bb.add_operation(IrAbstractBranch(taken=if_bb, not_taken=else_bb))

        next_bb = self.spawn_bb(
            set_as_active=True, label_hint=f"after_{self.active_bb.label}"
        )
        if_bb.add_outgoing_edge(next_bb)
        else_bb.add_outgoing_edge(next_bb)

        yield if_bb, else_bb
