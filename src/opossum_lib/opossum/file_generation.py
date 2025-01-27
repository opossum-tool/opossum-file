# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from opossum_lib.opossum.constants import (
    COMPRESSION_LEVEL,
    INPUT_JSON_NAME,
    OUTPUT_JSON_NAME,
)
from opossum_lib.opossum.opossum_file_content import OpossumFileContent


class OpossumFileWriter:
    @staticmethod
    def write_opossum_information_to_file(
        opossum_file_content: OpossumFileContent, file_path: Path
    ) -> None:
        with ZipFile(
            file_path, "w", compression=ZIP_DEFLATED, compresslevel=COMPRESSION_LEVEL
        ) as zip_file:
            OpossumFileWriter._write_input_json(opossum_file_content, zip_file)
            OpossumFileWriter._write_output_json_if_existing(
                opossum_file_content, zip_file
            )

    @staticmethod
    def _write_output_json_if_existing(
        opossum_file_content: OpossumFileContent, zip_file: ZipFile
    ) -> None:
        if opossum_file_content.output_file:
            zip_file.writestr(
                OUTPUT_JSON_NAME,
                opossum_file_content.output_file.model_dump_json(
                    exclude_none=True, indent=4, by_alias=True
                ),
            )

    @staticmethod
    def _write_input_json(
        opossum_file_content: OpossumFileContent, zip_file: ZipFile
    ) -> None:
        zip_file.writestr(
            INPUT_JSON_NAME,
            opossum_file_content.input_file.model_dump_json(
                indent=4,
                exclude_none=True,
                by_alias=True,
            ),
        )
