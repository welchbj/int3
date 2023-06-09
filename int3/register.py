from dataclasses import dataclass


@dataclass(frozen=True)
class Register:
    """Abstraction over an architecture register."""

    name: str
