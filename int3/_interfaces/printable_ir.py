from abc import ABC, abstractmethod


class PrintableIr(ABC):
    @abstractmethod
    def to_str(self, indent: int = 0) -> str: ...

    def indent_str(self, indent: int) -> str:
        spaces_per_level = 4
        return " " * indent * spaces_per_level

    def __str__(self) -> str:
        return self.to_str(indent=0)
