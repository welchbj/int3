import random
import string


def make_random_word(len_: int) -> bytes:
    alphabet = string.ascii_letters.encode()
    return bytes([random.choice(alphabet) for _ in range(len_)])
