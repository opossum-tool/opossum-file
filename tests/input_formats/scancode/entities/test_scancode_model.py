# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

from opossum_lib.input_formats.scancode.entities.scancode_model import (
    OptionsModel,
    ScancodeModel,
)


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
    assert getattr(options_model, "--license") is True
    assert getattr(options_model, "--email", False) is False


def test_scancode_model_accepts_minimal_converter_shape() -> None:
    scancode_model = ScancodeModel.model_validate(
        {
            "headers": [
                {
                    "end_timestamp": "2026-05-04T12:00:00",
                    "options": {
                        "input": ["."],
                        "--strip-root": True,
                    },
                }
            ],
            "license_references": [
                {
                    "spdx_license_key": "MIT",
                    "text": "MIT license text",
                }
            ],
            "files": [
                {
                    "path": "src/index.ts",
                    "type": "file",
                    "size": 1,
                    "copyrights": [{"copyright": "Copyright Example"}],
                    "urls": [
                        {
                            "start_line": 1,
                            "url": "https://example.com",
                        }
                    ],
                    "license_detections": [
                        {
                            "license_expression_spdx": "MIT",
                            "matches": [
                                {
                                    "start_line": 1,
                                    "end_line": 1,
                                    "score": 100,
                                    "license_expression_spdx": "MIT",
                                }
                            ],
                        }
                    ],
                    "package_data": [
                        {
                            "name": "demo",
                            "dependencies": [
                                {
                                    "purl": "pkg:npm/demo-dependency@1.0.0",
                                    "scope": "dependencies",
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    )

    assert scancode_model.headers[0].end_timestamp == "2026-05-04T12:00:00"
    assert scancode_model.files[0].path == "src/index.ts"
    assert scancode_model.license_references is not None
    assert scancode_model.license_references[0].spdx_license_key == "MIT"
