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

from opossum_lib.cli import extract_subtree, generate
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


class TestExtractSubtree:
    def _run_extraction(
        self,
        tmp_path: Path,
        subpath: str,
        opossumfile: str = "opossum_input.opossum",
        outputfile: str = "output.opossum",
    ) -> Result:
        runner = CliRunner()
        cmd_line_arguments = [
            str(test_data_path / opossumfile),
            subpath,
            "-o",
            str(tmp_path / outputfile),
        ]
        result = runner.invoke(extract_subtree, cmd_line_arguments)
        return result

    def test_successful_extraction(self, tmp_path: Path) -> None:
        result = self._run_extraction(tmp_path, "Frontend/Components")
        assert result.exit_code == 0

    def test_equivalency_of_subpaths(self, tmp_path: Path) -> None:
        result1 = self._run_extraction(
            tmp_path, "Frontend/Components", outputfile="out_basic"
        )
        result2 = self._run_extraction(
            tmp_path, "/Frontend/Components", outputfile="out_root"
        )
        result3 = self._run_extraction(
            tmp_path, "Frontend/Components/", outputfile="out_trailing"
        )

        assert result1.exit_code == 0
        assert result2.exit_code == 0
        assert result3.exit_code == 0

        with open(tmp_path / "out_basic.opossum", "rb") as inp:
            file_contents1 = inp.read()
        with open(tmp_path / "out_root.opossum", "rb") as inp:
            file_contents2 = inp.read()
        with open(tmp_path / "out_trailing.opossum", "rb") as inp:
            file_contents3 = inp.read()

        assert file_contents1 == file_contents2 == file_contents3
