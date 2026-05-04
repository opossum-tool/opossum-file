# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from zipfile import ZipFile

import pytest
from _pytest.logging import LogCaptureFixture
from click.testing import CliRunner, Result

from opossum_lib.cli import generate
from opossum_lib.core.services.write_opossum_file import write_opossum_file
from opossum_lib.shared.constants import (
    INPUT_JSON_NAME,
    OUTPUT_JSON_NAME,
)
from tests.setup.opossum_file_faker_setup import OpossumFileFaker
from tests.shared.comparison_helpers import _assert_equal_or_both_falsy

test_data_path = Path(__file__).resolve().parent / "data"


def run_with_command_line_arguments(cmd_line_arguments: list[str]) -> Result:
    runner = CliRunner()
    result = runner.invoke(generate, cmd_line_arguments)
    return result


class TestConvertOpossumFiles:
    def test_successful_conversion_of_input_only_opossum_file(
        self, tmp_path: Path
    ) -> None:
        output_file = str(tmp_path / "output_opossum.opossum")
        result = run_with_command_line_arguments(
            [
                "--opossum",
                str(test_data_path / "opossum_input.opossum"),
                "-o",
                output_file,
            ],
        )

        assert result.exit_code == 0
        expected_opossum_dict = _read_json_from_file("opossum_input.json")
        opossum_dict = _read_input_json_from_opossum(output_file)

        # Doing individual asserts as otherwise the diff viewer does no longer work
        # in case of errors
        _assert_expected_file_equals_generated_file(expected_opossum_dict, opossum_dict)

    def test_successful_conversion_of_input_and_output_opossum_file(
        self, tmp_path: Path
    ) -> None:
        output_file = str(tmp_path / "output_opossum.opossum")
        result = run_with_command_line_arguments(
            [
                "--opossum",
                str(test_data_path / "opossum_input_with_result.opossum"),
                "-o",
                output_file,
            ],
        )

        assert result.exit_code == 0

        # Doing individual asserts as otherwise the diff viewer does no longer work
        # in case of errors
        TestConvertOpossumFiles._assert_input_json_matches_expectations(output_file)
        TestConvertOpossumFiles._assert_output_json_matches_expectations(output_file)

    @staticmethod
    def _assert_input_json_matches_expectations(output_file: str) -> None:
        expected_opossum_dict = _read_json_from_file("opossum_input.json")
        opossum_dict = _read_input_json_from_opossum(output_file)
        _assert_expected_file_equals_generated_file(expected_opossum_dict, opossum_dict)

    @staticmethod
    def _assert_output_json_matches_expectations(output_file: str) -> None:
        expected_opossum_dict = _read_json_from_file("opossum_output.json")
        opossum_dict = _read_output_json_from_opossum(output_file)
        _assert_expected_file_equals_generated_file(expected_opossum_dict, opossum_dict)


class TestConvertScancodeFiles:
    def test_successful_conversion_of_scancode_file(self, tmp_path: Path) -> None:
        output_file = tmp_path / "output_scancode.opossum"
        result = run_with_command_line_arguments(
            [
                "--scan-code-json",
                str(test_data_path / "scancode_input.json"),
                "-o",
                str(output_file),
            ],
        )
        assert result.exit_code == 0
        assert output_file.exists()

    def test_successful_conversion_of_scancode_file_with_minimal_converter_shape(
        self, tmp_path: Path
    ) -> None:
        input_file = tmp_path / "scancode_input_minimal_shape.json"
        output_file = tmp_path / "output_scancode.opossum"
        scancode_json = _to_minimal_scancode_json(
            _read_json_from_file("scancode_input.json")
        )

        input_file.write_text(json.dumps(scancode_json), encoding="utf-8")

        result = run_with_command_line_arguments(
            [
                "--scan-code-json",
                str(input_file),
                "-o",
                str(output_file),
            ],
        )

        assert result.exit_code == 0
        assert output_file.exists()


def _to_minimal_scancode_json(scancode_json: Any) -> dict[str, Any]:
    def minimal_match(match: Any) -> dict[str, Any]:
        license_expression_spdx = match.get("license_expression_spdx")
        if license_expression_spdx is None:
            license_expression_spdx = match["spdx_license_expression"]
        minimal = {
            "start_line": match["start_line"],
            "end_line": match["end_line"],
            "score": match["score"],
            "license_expression_spdx": license_expression_spdx,
        }
        if match.get("matched_text"):
            minimal["matched_text"] = match["matched_text"]
        return minimal

    def minimal_license_detection(license_detection: Any) -> dict[str, Any]:
        return {
            "license_expression_spdx": license_detection["license_expression_spdx"],
            "matches": [
                minimal_match(match) for match in license_detection.get("matches", [])
            ],
        }

    def minimal_package(package: Any) -> dict[str, Any]:
        minimal = {
            key: package[key]
            for key in (
                "type",
                "namespace",
                "name",
                "version",
                "description",
                "homepage_url",
                "download_url",
                "code_view_url",
                "vcs_url",
                "copyright",
                "holder",
                "declared_license_expression_spdx",
                "other_license_expression_spdx",
                "notice_text",
                "repository_homepage_url",
                "purl",
            )
            if package.get(key) is not None
        }
        if package.get("license_detections") is not None:
            minimal["license_detections"] = [
                minimal_license_detection(license_detection)
                for license_detection in package["license_detections"]
            ]
        if package.get("dependencies") is not None:
            minimal["dependencies"] = [
                {
                    key: dependency[key]
                    for key in ("purl", "scope")
                    if dependency.get(key) is not None
                }
                for dependency in package["dependencies"]
            ]
        return minimal

    def minimal_file(file: Any) -> dict[str, Any]:
        minimal = {
            key: file[key]
            for key in ("path", "type", "size", "is_archive", "is_binary")
            if file.get(key) is not None
        }
        if file.get("copyrights") is not None:
            minimal["copyrights"] = [
                {"copyright": copyright["copyright"]}
                for copyright in file["copyrights"]
            ]
        if file.get("for_packages") is not None:
            minimal["for_packages"] = file["for_packages"]
        if file.get("license_detections") is not None:
            minimal["license_detections"] = [
                minimal_license_detection(license_detection)
                for license_detection in file["license_detections"]
            ]
        if file.get("package_data") is not None:
            minimal["package_data"] = [
                minimal_package(package) for package in file["package_data"]
            ]
        if file.get("urls") is not None:
            minimal["urls"] = [
                {
                    "start_line": url["start_line"],
                    "url": url["url"],
                }
                for url in file["urls"]
            ]
        return minimal

    options = {"input": scancode_json["headers"][0]["options"]["input"]}
    if scancode_json["headers"][0]["options"].get("--strip-root"):
        options["--strip-root"] = True
    if scancode_json["headers"][0]["options"].get("--full-root"):
        options["--full-root"] = True

    return {
        "headers": [
            {
                "end_timestamp": scancode_json["headers"][0]["end_timestamp"],
                "options": options,
            }
        ],
        "license_references": [
            {
                "spdx_license_key": license_reference["spdx_license_key"],
                "text": license_reference["text"],
            }
            for license_reference in scancode_json.get("license_references", [])
        ],
        "files": [
            *[minimal_file(file) for file in scancode_json["files"]],
            {
                "path": ".",
                "type": "directory",
                "size": 0,
            },
        ],
    }


def _read_input_json_from_opossum(output_file_path: str) -> Any:
    return _read_json_from_zip_file(output_file_path, INPUT_JSON_NAME)


def _read_output_json_from_opossum(output_file_path: str) -> Any:
    return _read_json_from_zip_file(output_file_path, OUTPUT_JSON_NAME)


def _read_json_from_zip_file(output_file_path: str, file_name: str) -> Any:
    with (
        ZipFile(output_file_path, "r") as z,
        z.open(file_name) as file,
    ):
        opossum_dict = json.load(file)
    return opossum_dict


def _read_json_from_file(filename: str) -> Any:
    with open(test_data_path / filename, encoding="utf-8") as file:
        expected_opossum_dict = json.load(file)
    return expected_opossum_dict


def _assert_expected_file_equals_generated_file(
    expected_opossum_dict: Any, opossum_dict: Any
) -> None:
    assert expected_opossum_dict.keys() == opossum_dict.keys()
    for field in expected_opossum_dict:
        _assert_equal_or_both_falsy(
            opossum_dict.get(field, None), expected_opossum_dict.get(field, None)
        )


class TestCliValidations:
    @staticmethod
    def generate_valid_scan_code_argument(
        filename: str = "scancode_input.json",
    ) -> list[str]:
        return ["--scan-code-json", str(test_data_path / filename)]

    @staticmethod
    def generate_valid_opossum_argument(
        filename: str = "opossum_input.opossum",
    ) -> list[str]:
        return ["--opossum", str(test_data_path / filename)]

    def test_cli_no_output_file_provided(
        self, opossum_file_faker: OpossumFileFaker
    ) -> None:
        runner = CliRunner()

        with runner.isolated_filesystem():
            file_path = "input.opossum"
            opossum_file = opossum_file_faker.opossum_file_content()
            write_opossum_file(opossum_file, Path(file_path))
            result = runner.invoke(
                generate,
                "--opossum " + file_path,
            )

            assert result.exit_code == 0
            assert Path.is_file(Path("output.opossum"))

    def test_cli_works_on_opossum_files_with_config_and_classification(self) -> None:
        result = run_with_command_line_arguments(
            TestCliValidations.generate_valid_opossum_argument(
                "opossum_input_with_classification.opossum"
            )
        )
        assert result.exit_code == 0

    @pytest.mark.parametrize(
        "options",
        [
            generate_valid_opossum_argument() + generate_valid_opossum_argument(),
            generate_valid_opossum_argument() + generate_valid_scan_code_argument(),
            generate_valid_scan_code_argument() + generate_valid_scan_code_argument(),
        ],
    )
    def test_cli_with_multiple_files(self, options: list[str]) -> None:
        result = run_with_command_line_arguments(options)
        assert result.exit_code == 0

    def test_cli_without_inputs(self, caplog: LogCaptureFixture) -> None:
        result = run_with_command_line_arguments(
            [
                "-o",
                "output.opossum",
            ],
        )
        assert result.exit_code == 0

        assert caplog.messages == ["No input provided. Exiting."]


class TestConvertOWASPFiles:
    def test_convert(self, tmp_path: Path) -> None:
        output_file = str(tmp_path / "output_owasp.opossum")
        result = run_with_command_line_arguments(
            [
                "--owasp-json",
                str(test_data_path / "dependency-check-report.json"),
                "-o",
                output_file,
            ],
        )

        assert result.exit_code == 0
