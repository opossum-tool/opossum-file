# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
import datetime
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
            metadata=_extract_metadata(owasp_model),
            resources=[],
        )
    )


def _extract_metadata(owasp_model: OWASPDependencyReportModel) -> Metadata:
    return Metadata(
        build_date=datetime.datetime.now().isoformat(),
        project_id=owasp_model.project_info.artifact_i_d or str(uuid.uuid4()),
        project_title=owasp_model.project_info.name,
        file_creation_date=owasp_model.project_info.report_date,
    )
