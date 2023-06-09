"""Library exception hierarchy."""


class Int3Error(Exception):
    """Base exception type for int3 library errors."""


class Int3MissingEntityError(Exception):
    """Exception type for missing entities."""


class Int3UnsupportedArchitecture(Exception):
    """Exception type for unsupported architectures."""


class Int3UnsupportedPlatform(Exception):
    """Exception type for unsupported platforms."""


class Int3WrappedKeystoneError(Exception):
    """A thin wrapper around KsError."""


class Int3WrappedCapstoneError(Exception):
    """A thin wrapper around CsError."""
