# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path

from opossum_lib.core.services.input_reader import InputReader
from opossum_lib.core.services.merge_opossums import merge_opossums
from opossum_lib.core.services.write_opossum_file import write_opossum_file


def generate_impl(input_readers: list[InputReader], output_file: Path) -> None:
    opossums = [reader.read() for reader in input_readers]
    opossum = opossums[0] if len(opossums) == 1 else merge_opossums(opossums)

    opossum_file_content = opossum.to_opossum_file_model()
    write_opossum_file(opossum_file_content, output_file)
