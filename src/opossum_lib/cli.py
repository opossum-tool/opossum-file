#!/usr/bin/env python3

# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0


import click

from opossum_lib.core.opossum_generator import (
    OpossumGenerationArguments,
    OpossumGenerator,
)


@click.group()
def opossum_file() -> None:
    pass


@opossum_file.command()
@click.option(
    "--opossum",
    "opossum_files",
    help="Specify a path to a .opossum file that you would like to "
    + "include in the final output. Option can be repeated.",
    multiple=True,
    type=click.Path(exists=True),
)
@click.option(
    "--scan-code-json",
    "scancode_json_files",
    help="Specify a path to a .json file generated by ScanCode that you would like to "
    + "include in the final output. Option can be repeated.",
    multiple=True,
    type=click.Path(exists=True),
)
@click.option(
    "--outfile",
    "-o",
    default="output.opossum",
    show_default=True,
    help="The file path to write the generated opossum document to. "
    'If appropriate, the extension ".opossum" will be appended.',
)
def generate(
    scancode_json_files: list[str],
    opossum_files: list[str],
    outfile: str,
) -> None:
    """
    Generate an Opossum file from various other file formats.

    \b
    Currently supported input formats:
      - ScanCode
      - Opossum
    """
    OpossumGenerator().generate(
        opossum_generation_arguments=OpossumGenerationArguments(
            spdx_files=[],
            opossum_files=opossum_files,
            scancode_json_files=scancode_json_files,
            outfile=outfile,
        )
    )


if __name__ == "__main__":
    opossum_file()
