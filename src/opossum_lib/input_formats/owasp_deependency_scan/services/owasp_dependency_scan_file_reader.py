# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
import json
import logging
import sys
from pathlib import Path

from opossum_lib.core.entities.opossum import Opossum
from opossum_lib.core.services.input_reader import InputReader
from opossum_lib.input_formats.owasp_deependency_scan.entities.owasp_dependency_report_model import (  # noqa: E501
    OWASPDependencyReportModel,
)
from opossum_lib.input_formats.owasp_deependency_scan.services.convert_to_opossum import (  # noqa: E501
    convert_to_opossum,
)


class OwaspDependencyScanFileReader(InputReader):
    path: Path

    def __init__(self, path: Path):
        self.path = path

    def read(self) -> Opossum:
        logging.info(f"Reading {self.path} as OWASP Dependency Scan")

        owasp_model = self._load_owasp_dependency_report_json()

        return convert_to_opossum(owasp_model)

    def _load_owasp_dependency_report_json(self) -> OWASPDependencyReportModel:
        try:
            with open(self.path) as input_file:
                json_data = json.load(input_file)
        except json.JSONDecodeError as e:
            logging.error(f"Error decoding json for file {self.path}. Message: {e.msg}")
            sys.exit(1)
        except UnicodeDecodeError:
            logging.error(f"Error decoding json for file {self.path}.")
            sys.exit(1)

        scancode_data = OWASPDependencyReportModel.model_validate(json_data)

        return scancode_data
