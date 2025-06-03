import logging
import os

# Allow for setting log level through environment variable.
if (level := os.environ.get("INT3_LOGLEVEL", None)) is not None:
    logging.basicConfig(
        format="[%(levelname)8s] %(message)s (%(filename)s:%(lineno)s)",
        level=level.upper(),
    )

# Initialize LLVM within llvmlite.
from llvmlite import binding as llvm

llvm.initialize()
llvm.initialize_all_targets()
llvm.initialize_all_asmprinters()

# Expose int3 library interface.
from .architecture import *
from .compilation import *
from .errors import *
from .execution import *
from .factor import *
from .format import *
from .meta import *
from .platform import *
from .triple import Triple
from .version import *
