# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

from opossum_lib.input_formats.scancode.entities.scancode_model import OptionsModel


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
