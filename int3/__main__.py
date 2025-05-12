import logging
import sys
from typing import BinaryIO

import click

from int3.architecture import ArchitectureMeta, ArchitectureMetas
from int3.assembly import assemble, disassemble
from int3.errors import Int3Error
from int3.execution import execute
from int3.format import FormatStyle, Formatter
from int3.strategy import Strategy


def _strategy_from_str(ctx, param, value: str):
    return Strategy.from_str(value)


def _architecture_from_str(ctx, param, value: str):
    return ArchitectureMetas.from_str(value)


def _format_style_from_str(ctx, param, value: str):
    return FormatStyle.from_str(value)


def _parse_bad_bytes(ctx, param, value: str):
    return Formatter(style_in=FormatStyle.Python, style_out=FormatStyle.Raw).format(
        value.encode()
    )


def _setup_logging(debug: bool):
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        format="[%(levelname)8s] %(message)s (%(filename)s:%(lineno)s)", level=level
    )


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

arch_meta_option = click.option(
    "--architecture",
    "-a",
    "arch_meta",
    help="Target architecture.",
    type=click.Choice(ArchitectureMetas.names()),
    callback=_architecture_from_str,
    default=ArchitectureMetas.from_host().name,
    show_default=True,
)

strategy_option = click.option(
    "--strategy",
    "-s",
    help="Code generation strategy.",
    type=click.Choice(Strategy.names()),
    callback=_strategy_from_str,
    default=Strategy.CodeSize.name,
    show_default=True,
)

format_in_option = click.option(
    "--format-in",
    help="The format of the input data.",
    type=click.Choice(FormatStyle.names()),
    callback=_format_style_from_str,
    default=FormatStyle.Raw.name,
    show_default=True,
)

format_out_option = click.option(
    "--format-out",
    help="The format of the output data.",
    type=click.Choice(FormatStyle.names()),
    callback=_format_style_from_str,
    default=FormatStyle.Python.name,
    show_default=True,
)

bad_bytes_option = click.option(
    "--bad-bytes",
    "-b",
    help="Bytes that should not appear in generated shellcodes.",
    callback=_parse_bad_bytes,
    default=b"",
    show_default=True,
)

debug_option = click.option(
    "--debug",
    is_flag=True,
    default=False,
    help="Enable debug logging to stderr.",
)


@cli.command("assemble")
@file_or_stdin_input_option
@arch_meta_option
@debug_option
def cli_assemble(input_file: BinaryIO, arch_meta: ArchitectureMeta, debug: bool):
    _setup_logging(debug)

    with input_file:
        asm_text: str = input_file.read().decode()

    asm_bytes = assemble(arch_meta=arch_meta, assembly=asm_text)
    click.echo(asm_bytes, nl=False)


@cli.command("assemble_repl")
@arch_meta_option
@debug_option
def cli_assemble_repl(arch_meta: ArchitectureMeta, debug: bool):
    _setup_logging(debug)

    # Attempt to import readline to provide history capability to input().
    try:
        import readline  # noqa
    except ImportError:
        pass

    formatter = Formatter(style_in=FormatStyle.Raw, style_out=FormatStyle.Python)

    while True:
        try:
            asm_text = input(">>> ")
            asm_bytes = assemble(arch_meta=arch_meta, assembly=asm_text)
            click.echo(formatter.format(asm_bytes))
        except Int3Error as e:
            click.echo(f"Error: {e}")
        except KeyboardInterrupt:
            click.echo("Quitting!")
            break


@cli.command("disassemble")
@file_or_stdin_input_option
@arch_meta_option
@debug_option
def cli_disassemble(input_file: BinaryIO, arch_meta: ArchitectureMeta, debug: bool):
    _setup_logging(debug)

    with input_file:
        machine_code: bytes = input_file.read()

    asm_text = disassemble(arch_meta=arch_meta, machine_code=machine_code)
    click.echo(asm_text)


@cli.command("format")
@file_or_stdin_input_option
@format_in_option
@format_out_option
@debug_option
def cli_format(
    input_file: BinaryIO, format_in: FormatStyle, format_out: FormatStyle, debug: bool
):
    _setup_logging(debug)

    with input_file:
        data: bytes = input_file.read()

    formatter = Formatter(style_in=format_in, style_out=format_out)

    if format_out is FormatStyle.Python:
        add_newline = True
    else:
        add_newline = False

    click.echo(formatter.format(data), nl=add_newline)


@cli.command("execute")
@file_or_stdin_input_option
@debug_option
def cli_execute(input_file: BinaryIO, debug: bool):
    _setup_logging(debug)

    with input_file:
        machine_code: bytes = input_file.read()

    execute(machine_code=machine_code)


if __name__ == "__main__":
    cli()
