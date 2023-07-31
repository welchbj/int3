import logging
import sys
from typing import BinaryIO, Type

import click

from int3.architectures import Architecture, Architectures
from int3.assembly import assemble, disassemble
from int3.context import Context
from int3.execution import execute
from int3.format import FormatStyle, Formatter
from int3.payloads import Payload
from int3.platforms import Platform, Platforms
from int3.strategy import Strategy


def _strategy_from_str(ctx, param, value: str):
    return Strategy.from_str(value)


def _platform_from_str(ctx, param, value: str):
    return Platforms.from_str(value)


def _architecture_from_str(ctx, param, value: str):
    return Architectures.from_str(value)


def _payload_cls_from_str(ctx, param, value: str):
    return Payload.cls_from_str(value)


def _format_style_from_str(ctx, param, value: str):
    return FormatStyle.from_str(value)


def _parse_bad_bytes(ctx, param, value: str):
    return Formatter(style_in=FormatStyle.Python, style_out=FormatStyle.Raw).format(
        value.encode()
    )


def _setup_logging(debug: bool):
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(format="[%(levelname)8s] %(message)s (%(filename)s:%(lineno)s)", level=level)


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

payload_option = click.option(
    "--payload",
    "payload_cls",
    help="The payload type to use.",
    callback=_payload_cls_from_str,
    type=click.Choice([cls.name() for cls in Payload.payload_cls_list()]),
    required=True,
)

debug_option = click.option(
    "--debug",
    is_flag=True,
    default=False,
    help="Enable debug logging to stderr.",
)


@cli.command("assemble")
@file_or_stdin_input_option
@platform_option
@architecture_option
@debug_option
def cli_assemble(input_file: BinaryIO, platform: Platform, architecture: Architecture, debug: bool):
    _setup_logging(debug)

    with input_file:
        asm_text: str = input_file.read().decode()

    ctx = Context(architecture=architecture, platform=platform)
    asm_bytes = assemble(ctx=ctx, assembly=asm_text)
    click.echo(asm_bytes, nl=False)


@cli.command("disassemble")
@file_or_stdin_input_option
@platform_option
@architecture_option
@debug_option
def cli_disassemble(
    input_file: BinaryIO, platform: Platform, architecture: Architecture, debug: bool
):
    _setup_logging(debug)

    with input_file:
        machine_code: bytes = input_file.read()

    ctx = Context(architecture=architecture, platform=platform)
    asm_text = disassemble(ctx=ctx, machine_code=machine_code)
    click.echo(asm_text)


@cli.command("format")
@file_or_stdin_input_option
@format_in_option
@format_out_option
@debug_option
def cli_format(input_file: BinaryIO, format_in: FormatStyle, format_out: FormatStyle, debug: bool):
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


@cli.command("encode")
@file_or_stdin_input_option
@debug_option
def cli_encode(input_file: BinaryIO, debug: bool):
    _setup_logging(debug)

    # TODO
    click.echo("Not yet implemented...")


# TODO: Each payload should probably be its own command, rather than the below system.


@cli.command("payload")
@bad_bytes_option
@format_out_option
@payload_option
@platform_option
@architecture_option
@strategy_option
@debug_option
def cli_payload(
    bad_bytes: bytes,
    format_out: FormatStyle,
    payload_cls: Type[Payload],
    platform: Platform,
    architecture: Architecture,
    strategy: Strategy,
    debug: bool,
):
    _setup_logging(debug)

    # TODO: Populate arch/platform based on the payload.

    ctx = Context(
        architecture=architecture,
        platform=platform,
        strategy=strategy,
        bad_bytes=bad_bytes,
    )

    payload = payload_cls(ctx=ctx)
    assembly = str(payload)

    if format_out == FormatStyle.Assembly:
        click.echo(assembly, nl=False)
    else:
        assembled_bytes = assemble(ctx=ctx, assembly=assembly)

        formatter = Formatter(style_in=FormatStyle.Raw, style_out=format_out)
        click.echo(formatter.format(assembled_bytes))


if __name__ == "__main__":
    cli()
