from __future__ import annotations

from dataclasses import dataclass

from int3.errors import Int3CodeGenerationError

from .instruction import Instruction
from .segment import Segment
from .strategy import Strategy

type Option = Instruction | Segment | Choice | FluidSegment


@dataclass(frozen=True)
class Choice:
    options: tuple[Option, ...]

    def choose(
        self, strategy: Strategy = Strategy.CompilationSpeed, bad_bytes: bytes = b""
    ) -> Segment:
        # TODO: Handle recursive choices and fluid segments

        match strategy:
            case Strategy.CompilationSpeed:
                # TODO
                raise NotImplementedError(
                    "CompilationSpeed strategy not yet implemented"
                )
            case Strategy.CodeSize:
                # TODO
                raise NotImplementedError("CodeSize strategy not yet implemented")

        # TODO
        raise Int3CodeGenerationError("TODO")

    # TODO: adding other choices


@dataclass(frozen=True)
class FluidSegment:
    def choose(
        self, strategy: Strategy = Strategy.CompilationSpeed, bad_bytes: bytes = b""
    ) -> Segment:
        # TODO
        ...
        raise Int3CodeGenerationError("TODO")
