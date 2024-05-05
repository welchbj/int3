from capstone import Cs, CsError

from int3.architectures import ArchitectureMeta
from int3.errors import Int3WrappedCapstoneError


def disassemble(arch_meta: ArchitectureMeta, machine_code: bytes) -> str:
    try:
        cs = Cs(arch=arch_meta.capstone_arch, mode=arch_meta.capstone_mode)
        instructions = list(cs.disasm(code=machine_code, offset=0))
    except CsError as e:
        raise Int3WrappedCapstoneError(str(e)) from e

    asm_text = "\n".join(
        f"{instr.address:#06x}: {instr.mnemonic} {instr.op_str}"
        for instr in instructions
    )
    return asm_text
