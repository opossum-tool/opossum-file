# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
import uuid

from opossum_lib.core.entities.metadata import Metadata
from opossum_lib.core.entities.opossum import Opossum
from opossum_lib.core.entities.scan_results import ScanResults
from opossum_lib.input_formats.owasp_deependency_scan.entities.owasp_dependency_report_model import (  # noqa: E501
    OWASPDependencyReportModel,
)


def convert_to_opossum(owasp_model: OWASPDependencyReportModel) -> Opossum:
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
