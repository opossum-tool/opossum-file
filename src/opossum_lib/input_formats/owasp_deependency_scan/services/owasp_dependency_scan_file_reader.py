# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
import json
import logging
import sys
import uuid
from pathlib import Path

from opossum_lib.core.entities.metadata import Metadata
from opossum_lib.core.entities.opossum import Opossum
from opossum_lib.core.entities.scan_results import ScanResults
from opossum_lib.core.services.input_reader import InputReader
from opossum_lib.input_formats.owasp_deependency_scan.entities.owasp_dependency_report_model import (  # noqa: E501
    OWASPDependencyReportModel,
)


class OwaspDependencyScanFileReader(InputReader):
    path: Path

    def __init__(self, path: Path):
        self.path = path

    def read(self) -> Opossum:
        logging.info(f"Reading {self.path} as OWASP Dependency Scan")

        owasp_model = self._load_owasp_dependency_report_json()
        print(owasp_model.model_dump_json(indent=4))

        return Opossum(
            scan_results=ScanResults(
                metadata=Metadata(
                    build_date="now",
                    project_id=str(uuid.uuid4()),
                    project_title="OWASP Dependency Scan",
                    file_creation_date="now",
                ),
                resources=[],
            )
        )

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
