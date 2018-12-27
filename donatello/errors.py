"""Custom exception types for the `donatello` library."""


class DonatelloError(Exception):
    """Base exception type for `donatello` errors."""

    def __init__(self, message, *args):
        self._message = message
        super(DonatelloError, self).__init__(self._message, *args)

    @property
    def message(self):
        """Error message to be shown to the end user."""
        return self._message


class DonatelloNoPresentBadCharactersError(DonatelloError):
    """An exception type for when a payload contains no bad characters."""


class DonatelloNoPossibleNopsError(DonatelloError):
    """An exception type for when no nops can be used with a bad char set."""


class DonatelloCannotEncodeError(DonatelloError):
    """An exception type for when encoding fails due to excessive bad chars."""
