"""Utility functions."""


def chunked(l, n):
    """Yield chunks of a specified size from a list.

    See:
        https://stackoverflow.com/a/312464/5094008

    Args:
        l (List): The list we wish to chunk.
        n (int): The size of each chunk.

    Returns:
        Generator[List]: The divided chunks of the initial list.

    """
    for i in range(0, len(l), n):
        yield l[i:i+n]
