# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path

from opossum_lib.input_formats.scancode.entities.scancode_model import (
    OptionsModel,
    ScancodeModel,
)

test_data_path = Path(__file__).resolve().parents[3] / "data"


def test_options_model_aliases_cli_args_correctly() -> None:
    options = {
        "input": ["/some/path"],
        "--strip-root": True,
        "--license": True,
        "strip_root": 1,
        "--strip_root": 2,
        "-strip-root": 3,
        "strip-root": 4,
    }
    options_model = OptionsModel.model_validate(options)
    assert options_model.input == ["/some/path"]
    assert options_model.strip_root is True
    assert options_model.license
    assert not options_model.email


def test_scancode_model_accepts_missing_unused_header_fields() -> None:
    with open(test_data_path / "scancode_input.json", encoding="utf-8") as file:
        scancode_json = json.load(file)

    del scancode_json["headers"][0]["message"]
    del scancode_json["headers"][0]["extra_data"]["system_environment"][
        "python_version"
    ]

    scancode_model = ScancodeModel.model_validate(scancode_json)

    assert scancode_model.headers[0].message is None
    system_environment = scancode_model.headers[0].extra_data.system_environment
    assert system_environment.python_version is None
