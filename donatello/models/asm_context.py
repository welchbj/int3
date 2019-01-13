"""Models for different assembly contexts."""

# TODO


class AbstractAsmContext(object):
    """An encapsulation of the assembly context of an instruction set.

    This is the core model that allows for a separation of encoding logic from
    a specific architecture/instruction set.

    Args:
        TODO

    """

    def __init__(self, bad_chars):
        # TODO
        pass

    def render(factor_chain):
        # TODO
        raise NotImplementedError(
            'subclasses of `AbstractAsmContext` must implement `render`')

    # TODO: properties for each of our encoding "recipes"

    # TODO: this should be abstract, and we extend it for each of the different
    #       supported instruction sets
