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


def _unwrap_single_option_choices(options: tuple[Option, ...]) -> tuple[Option, ...]:
    """Unwrap any nested single-option Choices to simplify structure."""
    unwrapped: list[Option] = []
    for option in options:
        if isinstance(option, Choice) and len(option.options) == 1:
            # Unwrap single-option Choice instances.
            unwrapped.append(option.options[0])
        else:
            unwrapped.append(option)
    return tuple(unwrapped)


def _format_items(
    class_name: str,
    items: tuple[Option, ...],
    indent: int = 0,
) -> str:
    """Format a collection of options/steps with proper indentation."""
    base_indent = " " * indent
    item_indent = " " * (indent + 4)

    lines = [f"{base_indent}<{class_name}["]

    for i, item in enumerate(items):
        is_last = i == len(items) - 1
        comma = "" if is_last else ","

        if isinstance(item, Instruction):
            # Single instruction: show inline with hex.
            insn_line = f"{item_indent}{item.to_str()}{comma}"
            lines.append(insn_line)
        elif isinstance(item, (Segment, Choice, FluidSegment)):
            # Nested structure: get its repr and indent it.
            nested_repr = repr(item)
            nested_lines = nested_repr.splitlines()

            lines.append(f"{item_indent}{nested_lines[0]}")
            for nested_line in nested_lines[1:]:
                lines.append(f"{item_indent}{nested_line}")
            if not is_last:
                lines[-1] += comma

    lines.append(f"{base_indent}]>")
    return "\n".join(lines)


@dataclass(frozen=True)
class Choice:
    options: tuple[Option, ...]

    def __post_init__(self) -> None:
        if len(self.options) == 0:
            raise Int3NoValidChoiceError(
                f"{self.__class__.__name__} must have at least one option"
            )

        unwrapped = _unwrap_single_option_choices(self.options)
        object.__setattr__(self, "options", unwrapped)

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

    def to_str(self, indent: int = 0) -> str:
        """Format all options with nesting represented via indentation."""
        return _format_items(self.__class__.__name__, self.options, indent)

    def __str__(self) -> str:
        return self.to_str()

    def __repr__(self) -> str:
        return self.to_str(indent=0)


@dataclass(frozen=True)
class FluidSegment:
    steps: tuple[Option, ...]

    def __post_init__(self) -> None:
        if len(self.steps) == 0:
            raise Int3NoValidChoiceError(
                f"{self.__class__.__name__} must have at least one step"
            )

        unwrapped = _unwrap_single_option_choices(self.steps)
        object.__setattr__(self, "steps", unwrapped)

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
                    f"Received options of differing triples: {inferred_triple} "
                    f"and {step.triple}"
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
            # In theory, this should be unreachable as long as we have some
            # options to pick from.
            raise Int3NoValidChoiceError(f"No choices presented within {self}")

        return Segment.from_insns(inferred_triple, *built_insns)

    def to_str(self, indent: int = 0) -> str:
        """Format all steps with nesting represented via indentation."""
        return _format_items(self.__class__.__name__, self.steps, indent)

    def __str__(self) -> str:
        return self.to_str()

    def __repr__(self) -> str:
        return self.to_str(indent=0)
