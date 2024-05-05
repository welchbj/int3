from dataclasses import dataclass

from int3.strategy import Strategy


@dataclass
class Compiler:
    # TODO: architecture

    strategy: Strategy = Strategy.CodeSize
    bad_bytes: bytes = b""
