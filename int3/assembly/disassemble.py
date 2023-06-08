from capstone import Cs, CsError

from int3.context import Context
from int3.errors import Int3WrappedCapstoneError


def disassemble(ctx: Context, machine_code: bytes) -> str:
    try:
        cs = Cs(
            arch=ctx.architecture.capstone_arch, mode=ctx.architecture.capstone_mode
        )
        instructions = list(cs.disasm(code=machine_code, offset=0))
    except CsError as e:
        raise Int3WrappedCapstoneError(str(e)) from e

    asm_text = "\n".join(
        f"{instr.address:#06x}: {instr.mnemonic} {instr.op_str}"
        for instr in instructions
    )
    return asm_text
