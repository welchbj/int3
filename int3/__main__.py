import sys
from typing import BinaryIO

import click


@click.group
def cli():
    pass


# Re-used option/argument definitions are created here and applied as
# decorators below.

file_or_stdin_input = click.option(
    "--input",
    "input_file",
    help="Input file. Omit this option to read from stdin.",
    type=click.File("r"),
    default=sys.stdin,
)

bad_bytes = click.option(
    # TODO
)


@cli.command()
@file_or_stdin_input
def assemble(input_file: BinaryIO):
    with input_file:
        raw_asm_bytes = input_file.read()

    click.echo("Not yet implemented...")


@cli.command()
@file_or_stdin_input
def disassemble(input_file: BinaryIO):
    # TODO
    click.echo("Not yet implemented...")


@cli.command()
@file_or_stdin_input
def format(input_file: BinaryIO):
    # TODO
    click.echo("Not yet implemented...")


@cli.command()
@file_or_stdin_input
def execute(input_file: BinaryIO):
    # TODO
    click.echo("Not yet implemented...")


@cli.command()
@file_or_stdin_input
def encode(input_file: BinaryIO):
    # TODO
    click.echo("Not yet implemented...")


@cli.command()
def payload():
    # TODO
    click.echo("Not yet implemented...")


@cli.command()
@file_or_stdin_input
def emulate(input_file: BinaryIO):
    # TODO: Incorporate Unicorn emulation.
    click.echo("Not yet implemented...")


if __name__ == "__main__":
    cli()
