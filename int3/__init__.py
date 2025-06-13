import logging
import os

# Allow for setting log level through environment variable.
if (level := os.environ.get("INT3_LOGLEVEL", None)) is not None:
    logging.basicConfig(
        format="[%(levelname)8s] %(message)s",
        level=level.upper(),
    )

import int3._vendored.llvmlite as llvmlite

# See: https://github.com/numba/llvmlite/issues/1162
llvmlite.opaque_pointers_enabled = True

from int3._vendored.llvmlite import binding as llvm

# Initialize LLVM features within llvmlite.
llvm.initialize()
llvm.initialize_all_targets()
llvm.initialize_all_asmprinters()
llvm.initialize_all_asmparsers()

# Expose int3 library interface.
from .architecture import *
from .compilation import *
from .errors import *
from .execution import *
from .factor import *
from .format import *
from .meta import *
from .platform import *
from .version import *
