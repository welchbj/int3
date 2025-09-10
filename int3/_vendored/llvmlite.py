from typing import Any

# These are mock versions of the parts of the llvmlite package we
# depend upon so that things like readthedocs can build the docs
# without building llvmlite from source.

class MockBindingInterface:
    @property
    def SectionIteratorRef(self) -> Any:
        return object()

    def initialize(self) -> None: ...
    def initialize_all_targets(self) -> None: ...
    def initialize_all_asmprinters(self) -> None: ...
    def initialize_all_asmparsers(self) -> None: ...


class MockIrInterface:
    @property
    def Constant(self) -> Any:
        return object()

    @property
    def Instruction(self) -> Any:
        return object()

    @property
    def LiteralStructType(self) -> Any:
        return object()

    @property
    def PointerType(self) -> Any:
        return object()

    @property
    def VoidType(self) -> Any:
        return object()


binding = MockBindingInterface()
ir = MockIrInterface()
