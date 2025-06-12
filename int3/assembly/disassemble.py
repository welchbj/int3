from capstone import Cs, CsError, CsInsn

from int3.architecture import Architecture
from int3.errors import Int3WrappedCapstoneError


def disassemble(arch: Architecture, machine_code: bytes) -> tuple[CsInsn, ...]:
    try:
        cs = Cs(arch=arch.capstone_arch, mode=arch.capstone_mode)
        cs.detail = True
        return tuple(cs.disasm(code=machine_code, offset=0))
    except CsError as e:
        raise Int3WrappedCapstoneError(str(e)) from e


def disassemble_to_str(arch: Architecture, machine_code: bytes) -> str:
    instructions = disassemble(arch, machine_code)
    asm_text = "\n".join(
        f"{instr.address:#06x}: {instr.mnemonic} {instr.op_str}"
        for instr in instructions
    )
    return asm_text
