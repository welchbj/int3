"""A simple gadget utility class."""


class Gadget(object):
    """A basic encapsulation of an assembly gadget.

    Args:
        required_chars: The characters that must be in the acceptable character
            set for this gadget to be used. This may be any type accepted as an
            argument by the `bytearray` builtin.
        asm_template (str): The format string template of the asm source
            corresponding to this gadget.

    """

    def __init__(self, required_chars, asm_template):
        self._required_chars = bytearray(required_chars)
        self._asm_template = asm_template

    def render(self, *operands):
        """Render this gadget into asm source code.

        Args:
            *operands (str): The operands to inject into this gadget's asm
                source template.

        Returns:
            str: The asm source of the `operand` argumnet injected into this
                class's `asm_template` property.

        """
        return self._asm_template.format(*operands)

    @property
    def required_chars(self):
        """The bytes/chars required to include this gadget in a shellcode.

        Note:
            This is used to specify the core bytes/characters used by this
            gadget and does not consider characters related to operands
            later injected into this gadget.

        Returns:
            bytearray: The byte/character set that must be a subset of the good
                 character set for this gadget to be usable.

        """
        return self._required_chars

    @property
    def asm_template(self):
        """A format string that can be formatted with this gadget's operand.

        Returns:
            str: The template format string.

        """
        return self._asm_template
