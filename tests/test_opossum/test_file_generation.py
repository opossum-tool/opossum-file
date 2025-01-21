# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
from zipfile import ZipFile

from opossum_lib.opossum.constants import INPUT_JSON_NAME, OUTPUT_JSON_NAME
from opossum_lib.opossum.file_generation import write_opossum_information_to_file
from opossum_lib.opossum.opossum_file_content import OpossumFileContent
from tests.test_setup.faker_setup import OpossumFaker


def test_only_input_information_available_writes_only_input_information(
    tmp_path: Path, opossum_faker: OpossumFaker
) -> None:
    opossum_file_content = OpossumFileContent(opossum_faker.opossum_file_information())
    output_path = tmp_path / "output.opossum"

    write_opossum_information_to_file(opossum_file_content, output_path)

    with ZipFile(output_path, "r") as zip_file:
        assert zip_file.namelist() == [INPUT_JSON_NAME]


def test_input_and_output_information_available_writes_both(
    tmp_path: Path, opossum_faker: OpossumFaker
) -> None:
    opossum_file_content = opossum_faker.opossum_file_content()
    output_path = tmp_path / "output.opossum"

    write_opossum_information_to_file(opossum_file_content, output_path)

    with ZipFile(output_path, "r") as zip_file:
        assert INPUT_JSON_NAME in zip_file.namelist()
        assert OUTPUT_JSON_NAME in zip_file.namelist()
