# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0


import pytest
from _pytest.logging import LogCaptureFixture

from opossum_lib.input_formats.scancode.services.convert_to_opossum import (
    convert_to_opossum,
)
from tests.setup.scancode_faker_setup import ScanCodeFaker


class TestExtractScancodeHeader:
    def test_produces_expected_result(
        self,
        scancode_faker: ScanCodeFaker,
    ) -> None:
        scancode_data = scancode_faker.scancode_data()
        opossum = convert_to_opossum(
            scancode_data,
        )
        metadata = opossum.scan_results.metadata
        header = scancode_data.headers[0]
        assert metadata.file_creation_date == header.end_timestamp
        assert metadata.project_title == "ScanCode file"

    def test_errors_with_missing_header(
        self, caplog: LogCaptureFixture, scancode_faker: ScanCodeFaker
    ) -> None:
        scancode_data = scancode_faker.scancode_data(headers=[])

        with pytest.raises(SystemExit):
            convert_to_opossum(scancode_data)

        assert "header" in caplog.messages[0].lower()

    def test_error_with_multiple_headers(
        self, caplog: LogCaptureFixture, scancode_faker: ScanCodeFaker
    ) -> None:
        header1 = scancode_faker.header()
        header2 = scancode_faker.header()
        scancode_data = scancode_faker.scancode_data(headers=[header1, header2])

        with pytest.raises(SystemExit):
            convert_to_opossum(scancode_data)

        assert "header" in caplog.messages[0].lower()


class TestConvertToOpossumFull:
    def test_convert(
        self,
        scancode_faker: ScanCodeFaker,
    ) -> None:
        scancode_data = scancode_faker.scancode_data()
        opossum_data = convert_to_opossum(scancode_data)

        assert opossum_data.review_results is None
        scan_results = opossum_data.scan_results
        assert len(list(scan_results.resources.all_resources())) == len(
            scancode_data.files
        )
        num_attributions = sum(
            len(resource.attributions)
            for resource in scan_results.resources.all_resources()
        )
        num_license_detections = sum(
            len(f.license_detections) for f in scancode_data.files
        )
        assert num_attributions == num_license_detections
