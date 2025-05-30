from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING

from int3._interfaces import PrintableIr
from int3.architecture import Architecture
from int3.errors import Int3IrMismatchedTypeError
from int3.ir import (
    HlirAnyType,
    HlirBranchOperator,
    HlirIntConstant,
    HlirIntVariable,
    HlirLabel,
    HlirOperation,
    HlirOperator,
    LlirAnyType,
    LlirConstant,
    LlirLabel,
    LlirOperation,
    LlirOperator,
    LlirVirtualRegister,
)

if TYPE_CHECKING:
    from int3.compilation import Block, Compiler, Function, Scope


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class FlattenedProgram(PrintableIr):
    functions: tuple[FlattenedFunction, ...]

    def to_str(self, indent: int = 0) -> str:
        indent_str = self.indent_str(indent)
        return f"\n{indent_str}".join(str(func) for func in self.functions)


@dataclass(frozen=True)
class FlattenedFunction(PrintableIr):
    name: str
    ledger: tuple[LlirOperation | LlirLabel, ...]
    vreg_to_op_map: dict[LlirVirtualRegister, LlirOperation]

    @staticmethod
    def from_func(func: "Function", arch: Architecture) -> FlattenedFunction:
        llir_ops: list[LlirOperation | LlirLabel] = []

        # Setup lookup tables for relationships between scopes
        # and blocks.
        scope_to_block_label_map: dict[int, set[str]] = defaultdict(set)
        for block in func.blocks:
            # Record the scopes this block holds a reference to.
            for scope in block.scope_stack:
                scope_to_block_label_map[id(scope)].add(block.label.name)

        # Counter used for generating vreg names.
        vreg_idx = 0

        # Lookup tables for:
        #   - HLIR vars to LLIR vregs
        #   - vreg definitions to associated LLIR operations
        #   - Scopes to associated vregs
        var_to_vreg_map: dict[str, LlirVirtualRegister] = {}
        vreg_to_op_map: dict[LlirVirtualRegister, LlirOperation] = {}
        scope_to_vreg_list_map: dict[int, list[LlirVirtualRegister]] = defaultdict(list)

        def _alloc_vreg() -> LlirVirtualRegister:
            nonlocal vreg_idx
            new_vreg = LlirVirtualRegister(f"vreg{vreg_idx}")
            vreg_idx += 1
            return new_vreg

        def _map_llir_ops(
            operator: LlirOperator, vregs: list[LlirVirtualRegister]
        ) -> list[LlirOperation]:
            return [
                LlirOperation(operator=operator, result=None, args=(vreg,))
                for vreg in vregs
            ]

        def _translate_hlir_arg(hlir_arg: HlirAnyType | HlirLabel) -> LlirAnyType:
            llir_arg: LlirAnyType

            if isinstance(hlir_arg, HlirIntVariable):
                llir_arg = var_to_vreg_map[hlir_arg.name]
            elif isinstance(hlir_arg, HlirIntConstant):
                llir_arg = LlirConstant(
                    signed=hlir_arg.signed,
                    bit_size=hlir_arg.bit_size,
                    value=hlir_arg.value,
                )
            elif isinstance(hlir_arg, HlirLabel):
                llir_arg = LlirLabel(name=hlir_arg.name)
            else:
                raise NotImplementedError(
                    f"HLIR argument translation for {hlir_arg.__class__.__name__} not implemented"
                )

            return llir_arg

        for block in func.blocks:
            logger.debug(f"Entering block {block.label}")

            scope_vars = list(block.lowest_scope.var_map.values())
            logger.debug(f"Block {block.label} defines {len(scope_vars)} variables")

            # Record this block's label.
            llir_ops.append(LlirLabel(name=block.label.name))

            # Virtual registers created for this block's scope.
            new_vregs: list[LlirVirtualRegister] = []

            # Map this block's HLIR variables to LLIR vregs.
            for hlir_var_name, hlir_var in block.lowest_scope.var_map.items():
                # The most direct case: we're dealing with a HLIR var of the
                # architecture's target width.
                if (
                    isinstance(hlir_var, HlirIntVariable)
                    and hlir_var.bit_size == arch.bit_size
                ):
                    new_vreg = _alloc_vreg()
                    var_to_vreg_map[hlir_var_name] = new_vreg
                    new_vregs.append(new_vreg)

                    logger.debug(
                        f"Allocated vreg {new_vreg.name} for var {hlir_var_name}"
                    )
                else:
                    # XXX: If dealing with ints of non-native widths or bytes, we will
                    #      have to emulate them in vregs differently.
                    raise NotImplementedError(
                        "Currently only support variables of native arch width"
                    )

            # Record birth operations for this block's new vregs.
            llir_ops.extend(_map_llir_ops(LlirOperator.Birth, new_vregs))
            scope_to_vreg_list_map[id(block.lowest_scope)].extend(new_vregs)

            # Translate this block's HLIR operations to LLIR operations.
            for hlir_op in block.operations:
                match hlir_op.operator:
                    case HlirBranchOperator.LessThan:
                        # TODO: Emit correct code
                        llir_oper = LlirOperator.Nop
                    case HlirOperator.Mov:
                        llir_oper = LlirOperator.Mov
                    case HlirOperator.Syscall:
                        # TODO: Need to emit locking.
                        llir_oper = LlirOperator.Syscall
                    case HlirOperator.Jump:
                        # TODO: Control flow disruption operations break the injected Kill ops at
                        #       the end of scope.
                        llir_oper = LlirOperator.Jump
                    case _:
                        raise NotImplementedError(
                            f"HLIR operator {hlir_op.operator} translation not implemented"
                        )

                # Translate HLIR arguments to LLIR.
                llir_args: list[LlirAnyType] = []
                for hlir_arg in hlir_op.args:
                    llir_args.append(_translate_hlir_arg(hlir_arg))

                if isinstance(hlir_op, HlirOperation):
                    if hlir_op.result is None:
                        llir_result = None
                    else:
                        llir_result = _translate_hlir_arg(hlir_op.result)
                else:
                    llir_result = None

                if isinstance(llir_result, LlirConstant):
                    raise Int3IrMismatchedTypeError(
                        f"Unexpected type {llir_result.__class__.__name__} as LLIR op result"
                    )

                llir_ops.append(
                    LlirOperation(
                        operator=llir_oper, result=llir_result, args=tuple(llir_args)
                    )
                )

            # Remove this block's reference on each of its potential scopes. For scopes
            # that have had all references removed, we can kill all of their associated vregs.
            for scope in block.scope_stack:
                lingering_scope_refs = scope_to_block_label_map[id(scope)]
                lingering_scope_refs.remove(block.label.name)

                if not lingering_scope_refs:
                    # This scope no longer has any references from blocks. We
                    # can kill all vregs associated with this scope.
                    vregs_for_scope = scope_to_vreg_list_map[id(scope)]
                    llir_ops.extend(_map_llir_ops(LlirOperator.Kill, vregs_for_scope))

                    scope_to_block_label_map.pop(id(scope))
                    scope_to_vreg_list_map.pop(id(scope))

        return FlattenedFunction(
            name=func.name, ledger=tuple(llir_ops), vreg_to_op_map=vreg_to_op_map
        )

    def to_str(self, indent: int = 0) -> str:
        indent_str = self.indent_str(indent)

        text = f"{indent_str}func {self.name}:\n"
        for op in self.ledger:
            if isinstance(op, LlirLabel):
                text += op.to_str(indent=indent)
                text += ":"
            else:
                text += op.to_str(indent=indent + 1)
            text += "\n"

        return text


@dataclass
class Flattener:
    compiler: "Compiler"

    def flatten(self) -> FlattenedProgram:
        flattened_functions: list[FlattenedFunction] = []

        for func_name, func in self.compiler.func.func_map.items():
            logger.debug(f"Performing function flatten on {func_name}...")
            flattened_functions.append(
                FlattenedFunction.from_func(func, arch=self.compiler.arch)
            )

        return FlattenedProgram(functions=tuple(flattened_functions))
