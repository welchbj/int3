"""Library exception hierarchy."""


class Int3Error(Exception):
    """Base exception type for int3 library errors."""


class Int3MissingEntityError(Int3Error):
    """Exception type for missing entities."""


class Int3UnsupportedSyscall(Int3MissingEntityError):
    """Except type for an unsupported syscall in a given context."""


class Int3WrappedKeystoneError(Int3Error):
    """A thin wrapper around KsError."""


class Int3WrappedCapstoneError(Int3Error):
    """A thin wrapper around CsError."""


class Int3ArgumentError(Int3Error):
    """Exception type for invalid arguments."""


class Int3InsufficientWidthError(Int3ArgumentError):
    """Exception type for arguments that can't be represented with given constraints."""


class Int3UnsupportedFormatError(Int3ArgumentError):
    """Exception type for formats not supported in some functionality."""


class Int3SatError(Int3Error):
    """Exception type for satisfiability errors."""


class Int3CompilationError(Int3Error):
    """Exception type for IR compilation errors."""


class Int3CodeGenerationError(Int3Error):
    """Exception type for code generation errors."""


class Int3UnsuitableCodeMutation(Int3CodeGenerationError):
    """Exception type for when code mutations should not / cannot be applied."""


class Int3ProgramDefinitionError(Int3Error):
    """Exception type for program definition errors."""


class Int3ContextError(Int3ProgramDefinitionError):
    """Exception type for invalid use of context managers."""


class Int3TypeCoercionError(Int3ProgramDefinitionError):
    """Exception type for type coercion errors and failures."""
