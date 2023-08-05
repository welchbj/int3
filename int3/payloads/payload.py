from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Type

from int3.context import Context
from int3.errors import Int3MissingEntityError

_PAYLOAD_MAP: dict[str, Type[Payload]] = {}


@dataclass
class Payload(ABC):
    ctx: Context

    # TODO: How to have per-payload arguments?

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)

        _PAYLOAD_MAP[cls.name()] = cls

    @classmethod
    def cls_from_str(cls, name: str) -> Type[Payload]:
        payload_cls = _PAYLOAD_MAP.get(name, None)
        if payload_cls is None:
            raise Int3MissingEntityError(f"No such payload {name}")

        return payload_cls

    @classmethod
    def payload_cls_list(cls) -> list[Type[Payload]]:
        return list(_PAYLOAD_MAP.values())

    @classmethod
    @abstractmethod
    def name(cls) -> str:
        """The shorthand name of this payload."""

    # TODO: Specify permitted architectures and platforms in a class-level
    #       property.

    @abstractmethod
    def __str__(self) -> str:
        """Generate the payload's logic as assembly code."""
