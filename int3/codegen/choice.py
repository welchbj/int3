from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from int3.errors import Int3MismatchedTripleError, Int3NoValidChoiceError

from .instruction import Instruction
from .segment import Segment
from .strategy import Strategy

if TYPE_CHECKING:
    from int3.platform import Triple

type Option = Instruction | Segment | Choice | FluidSegment


@dataclass(frozen=True)
class Choice:
    options: tuple[Option, ...]

    def choose(
        self, strategy: Strategy = Strategy.CompilationSpeed, bad_bytes: bytes = b""
    ) -> Segment:
        if strategy != Strategy.CompilationSpeed:
            raise NotImplementedError("Only CompilationSpeed strategy is implemented")

        for option in self.options:
            if isinstance(option, (Instruction, Segment)):
                if option.is_dirty(bad_bytes):
                    continue

                # For single Instructions, we wrap them in a Segment so this
                # method can have a unified return type.
                if isinstance(option, Instruction):
                    option = Segment.from_insns(option.triple, option)

                # Return the first clean concrete option.
                return option
            else:
                # Unwrap the inner Choice or FluidSegment into a concrete Segment.
                selected = option.choose(strategy, bad_bytes)
                if selected.is_dirty(bad_bytes):
                    continue

                return selected

        raise Int3NoValidChoiceError(f"No valid options presented in {self}")

    # TODO: A good __str__ / __repr__


@dataclass(frozen=True)
class FluidSegment:
    steps: tuple[Option, ...]

    def choose(
        self, strategy: Strategy = Strategy.CompilationSpeed, bad_bytes: bytes = b""
    ) -> Segment:
        built_insns: list[Instruction] = []
        inferred_triple: Triple | None = None

        for step in self.steps:
            if isinstance(step, (Choice, FluidSegment)):
                step = step.choose(strategy, bad_bytes)

            if inferred_triple is None:
                inferred_triple = step.triple
            elif inferred_triple != step.triple:
                raise Int3MismatchedTripleError(
                    f"Received options of differing triples: {inferred_triple} and {step.triple}"
                )

            # We are now dealing with either a concrete Instruction or Segment.

            if step.is_dirty(bad_bytes):
                raise Int3NoValidChoiceError(
                    f"Cannot overcome bad bytes in step: {step}"
                )

            # Record the new concrete instruction(s).
            if isinstance(step, Instruction):
                built_insns.append(step)
            else:
                built_insns.extend(step.insns)

        if inferred_triple is None:
            # In theory, this should be unreachable as long as we have some options to pick from.
            raise Int3NoValidChoiceError(f"No choices presented within {self}")

        return Segment.from_insns(inferred_triple, *built_insns)

    # TODO: A good __str__ / __repr__
