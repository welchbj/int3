import logging
import os

# Allow for setting log level through environment variable.
if (level := os.environ.get("INT3_LOGLEVEL", None)) is not None:
    logging.basicConfig(
        format="[%(levelname)8s] %(message)s (%(filename)s:%(lineno)s)", level=level
    )

from .architecture import *
from .codegen import *
from .compilation import *
from .errors import *
from .execution import *
from .factor import *
from .format import *
from .ir import *
from .meta import *
from .platform import *
from .version import *
