from int3.gadgets import Gadget
from int3.immediates import IntImmediate
from int3.registers import Registers

from .architecture_emitter import ArchitectureEmitter


class IntelEmitterMixin(ArchitectureEmitter[Registers]):
    def literal_mov(self, dst: Registers, src: Registers | IntImmediate) -> Gadget:
        if dst == self.arch.sp_reg:
            self.current_stack_scope.is_corrupted = True

        src_str = hex(src) if isinstance(src, IntImmediate) else src
        return Gadget(f"mov {dst}, {src_str}")

    def literal_load(
        self, dst: Registers, src_ptr: Registers, offset: int = 0
    ) -> Gadget:
        if dst == self.arch.sp_reg:
            self.current_stack_scope.is_corrupted = True

        if offset == 0:
            load_addr = f"[{src_ptr}]"
        else:
            load_addr = f"[{src_ptr}+{hex(offset)}]"

        return Gadget(f"mov {dst}, {load_addr}")

    def literal_store(
        self, dst: Registers, src: Registers | IntImmediate, offset: int = 0
    ) -> Gadget:
        if dst == self.arch.sp_reg:
            self.current_stack_scope.is_corrupted = True

        if offset == 0:
            store_addr = f"[{dst}]"
        else:
            store_addr = f"[{dst}+{hex(offset)}]"

        return Gadget(f"mov {store_addr}, {src}")

    def literal_push(self, value: Registers | IntImmediate) -> Gadget:
        value_str = hex(value) if isinstance(value, IntImmediate) else value
        return Gadget(f"push {value_str}", stack_change=-self.arch.byte_size)

    def literal_pop(self, result: Registers) -> Gadget:
        return Gadget(f"pop {result}", stack_change=self.arch.byte_size)

    def literal_add(self, dst: Registers, operand: Registers | IntImmediate) -> Gadget:
        stack_change = 0
        if dst == self.arch.sp_reg:
            if isinstance(operand, IntImmediate):
                stack_change = operand
            else:
                self.current_stack_scope.is_corrupted = True

        operand_str = hex(operand) if isinstance(operand, IntImmediate) else operand
        return Gadget(f"add {dst}, {operand_str}", stack_change=stack_change)

    def literal_sub(self, dst: Registers, operand: Registers | IntImmediate) -> Gadget:
        stack_change = 0
        if dst == self.arch.sp_reg:
            if isinstance(operand, IntImmediate):
                stack_change = -operand
            else:
                self.current_stack_scope.is_corrupted = True

        operand_str = hex(operand) if isinstance(operand, IntImmediate) else operand
        return Gadget(f"sub {dst}, {operand_str}", stack_change=stack_change)

    def literal_xor(self, dst: Registers, operand: Registers | IntImmediate) -> Gadget:
        if dst == self.arch.sp_reg:
            self.current_stack_scope.is_corrupted = True

        operand_str = hex(operand) if isinstance(operand, IntImmediate) else operand
        return Gadget(f"xor {dst}, {operand_str}")

    def literal_neg(self, dst: Registers) -> Gadget:
        if dst == self.arch.sp_reg:
            self.current_stack_scope.is_corrupted = True

        return Gadget(f"neg {dst}")

    def literal_call(self, target: Registers) -> Gadget:
        return Gadget(f"call {target}", stack_change=-self.arch.byte_size)

    def literal_breakpoint(self) -> Gadget:
        return Gadget("int3")

    def literal_ret(self) -> Gadget:
        return Gadget("ret", stack_change=self.arch.byte_size)
