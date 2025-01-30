# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path

import pytest
from _pytest.logging import LogCaptureFixture

from opossum_lib.input_formats.opossum.services.opossum_format_reader import (
    OpossumFormatReader,
)

TEST_DATA_DIR = Path(__file__).resolve().parent.parent.parent.parent.parent / "data"


def test_read_opossum_file_corrupted_file_exits_1(caplog: LogCaptureFixture) -> None:
    input_path = TEST_DATA_DIR / "opossum_input_corrupt.opossum"
    opossum_format_reader = OpossumFormatReader(input_path)

    with pytest.raises(SystemExit) as system_exit:
        opossum_format_reader.read()
    assert system_exit.value.code == 1
    assert "is corrupt and does not contain 'input.json'" in caplog.messages[0]


def test_read_opossum_file_containing_output_json() -> None:
    input_path = TEST_DATA_DIR / "opossum_input_with_result.opossum"
    opossum_format_reader = OpossumFormatReader(input_path)

    result = opossum_format_reader.read()

    assert result is not None
    assert result.scan_results is not None
    assert result.review_results is not None
