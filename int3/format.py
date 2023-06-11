from dataclasses import dataclass
from enum import Enum, auto


class FormatStyle(Enum):
    Raw = auto()
    Hex = auto()
    Python = auto()


@dataclass
class Formatter:
    style_in: FormatStyle | str
    style_out: FormatStyle | str

    def __post_init__(self):
        # TODO
        pass
