from dataclasses import dataclass

from .block import Block
from .scope import Scope


@dataclass
class Function:
    num_args: int

    # TODO: Do we track blocks and scopes here?
