import itertools
from typing import Iterator


def grouper(iterator: Iterator, n: int) -> Iterator[list]:
    """Chunk an iterator into iterators of length n.

    See: https://stackoverflow.com/a/71951567

    """
    while chunk := list(itertools.islice(iterator, n)):
        yield chunk
