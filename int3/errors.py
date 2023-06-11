"""Library exception hierarchy."""


class Int3Error(Exception):
    """Base exception type for int3 library errors."""


class Int3MissingEntityError(Int3Error):
    """Exception type for missing entities."""


class Int3UnsupportedArchitecture(Int3Error):
    """Exception type for unsupported architectures."""


class Int3UnsupportedPlatform(Int3Error):
    """Exception type for unsupported platforms."""


class Int3WrappedKeystoneError(Int3Error):
    """A thin wrapper around KsError."""


class Int3AssemblyError(Int3Error):
    """Assembly errors that didn't originate from a keystone exception."""


class Int3WrappedCapstoneError(Int3Error):
    """A thin wrapper around CsError."""
