from typing import NoReturn

import int3


def shellcode(emitter: int3.Windowsx86Emitter) -> bytes:
    emitter.resolve_dll(name="kernel.dll", dst="eax")

    return bytes(emitter)


def main() -> NoReturn:
    # TODO: Support transparent option between x86 and x86_64?

    ctx = int3.Context(
        architecture=int3.Architectures.from_host(),
        platform=int3.Platforms.from_host(),
    )
    int3.execute(shellcode(int3.Windowsx86Emitter(ctx)))


if __name__ == "__main__":
    main()
