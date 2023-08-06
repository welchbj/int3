"""Library exception hierarchy."""


class Int3Error(Exception):
    """Base exception type for int3 library errors."""


class Int3MissingEntityError(Int3Error):
    """Exception type for missing entities."""


class Int3UnsupportedArchitecture(Int3MissingEntityError):
    """Exception type for unsupported architectures."""


class Int3UnsupportedPlatform(Int3MissingEntityError):
    """Exception type for unsupported platforms."""


class Int3WrappedKeystoneError(Int3Error):
    """A thin wrapper around KsError."""


class Int3AssemblyError(Int3Error):
    """Assembly errors that didn't originate from a keystone exception."""


class Int3WrappedCapstoneError(Int3Error):
    """A thin wrapper around CsError."""


class Int3ArgumentError(Int3Error):
    """Exception type for invalid arguments."""


class Int3InsufficientWidthError(Int3ArgumentError):
    """Exception type for arguments that can't be represented with given constraints."""


class Int3UnsupportedFormatError(Int3ArgumentError):
    """Exception type for formats not supported in some functionality."""


class Int3LockedRegisterError(Int3ArgumentError):
    """Exception type for attempting to use a locked register."""


class Int3AmbiguousContextError(Int3ArgumentError):
    """Exception type for ambiguous sets of arguments."""


class Int3SatError(Int3Error):
    """Exception type for satisfiability errors."""
