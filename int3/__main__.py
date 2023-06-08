import sys
from typing import BinaryIO

import click

from int3.assembly import assemble, disassemble
from int3.architectures import Architecture, Architectures
from int3.context import Context
from int3.execution import execute
from int3.platforms import Platform, Platforms


def _platform_from_str(ctx, param, value: str):
    return Platforms.from_str(value)


def _architecture_from_str(ctx, param, value: str):
    return Architectures.from_str(value)


@click.group
def cli():
    pass


# Re-used option/argument definitions are created here and applied as
# decorators below.

file_or_stdin_input_option = click.option(
    "--input",
    "-i",
    "input_file",
    help="Input file. Omit this option to read from stdin.",
    type=click.File("rb"),
    default=sys.stdin.buffer,
)

platform_option = click.option(
    "--platform",
    "-p",
    help="Target platform.",
    type=click.Choice(Platforms.names()),
    callback=_platform_from_str,
    default=Platforms.from_host().name,
    show_default=True,
)

architecture_option = click.option(
    "--architecture",
    "-a",
    help="Target architecture.",
    type=click.Choice(Architectures.names()),
    callback=_architecture_from_str,
    default=Architectures.from_host().name,
    show_default=True,
)

bad_bytes_option = click.option(
    # TODO
)


@cli.command("assemble")
@file_or_stdin_input_option
@platform_option
@architecture_option
def cli_assemble(input_file: BinaryIO, platform: Platform, architecture: Architecture):
    with input_file:
        asm_text: str = input_file.read().decode()

    # TODO: Other ctx arguments.
    ctx = Context(architecture=architecture, platform=platform)

    asm_bytes = assemble(ctx=ctx, assembly=asm_text)
    click.echo(asm_bytes, nl=False)


@cli.command("disassemble")
@file_or_stdin_input_option
@platform_option
@architecture_option
def cli_disassemble(
    input_file: BinaryIO, platform: Platform, architecture: Architecture
):
    with input_file:
        machine_code: bytes = input_file.read()

    # TODO: Other ctx arguments.
    ctx = Context(architecture=architecture, platform=platform)

    asm_text = disassemble(ctx=ctx, machine_code=machine_code)
    click.echo(asm_text)


@cli.command("format")
@file_or_stdin_input_option
def cli_format(input_file: BinaryIO):
    # TODO
    click.echo("Not yet implemented...")


@cli.command("execute")
@file_or_stdin_input_option
def cli_execute(input_file: BinaryIO):
    with input_file:
        machine_code: bytes = input_file.read()

    execute(machine_code=machine_code)


@cli.command("encode")
@file_or_stdin_input_option
def cli_encode(input_file: BinaryIO):
    # TODO
    click.echo("Not yet implemented...")


@cli.command("payload")
def cli_payload():
    # TODO
    click.echo("Not yet implemented...")


if __name__ == "__main__":
    cli()
