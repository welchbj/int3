from dataclasses import dataclass


class Implication:
    pass


@dataclass(frozen=True)
class StaticImplication(Implication):
    bytes: bytes


@dataclass(frozen=True)
class RegisterImplication(Implication):
    register: str
    bytes: bytes


@dataclass(frozen=True)
class ImmediateImplication(Implication):
    # TODO: This will probably have to be dynamic.

    immediate: int
    bytes: bytes
