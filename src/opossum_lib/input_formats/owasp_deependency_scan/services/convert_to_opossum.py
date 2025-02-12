# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
import datetime
import uuid
from pathlib import PurePath

from opossum_lib.core.entities.external_attribution_source import (
    ExternalAttributionSource,
)
from opossum_lib.core.entities.metadata import Metadata
from opossum_lib.core.entities.opossum import Opossum
from opossum_lib.core.entities.opossum_package import OpossumPackage
from opossum_lib.core.entities.resource import Resource, ResourceType
from opossum_lib.core.entities.root_resource import RootResource
from opossum_lib.core.entities.scan_results import ScanResults
from opossum_lib.core.entities.source_info import SourceInfo
from opossum_lib.input_formats.owasp_deependency_scan.entities.owasp_dependency_report_model import (  # noqa: E501
    DependencyModel,
    OWASPDependencyReportModel,
)


def convert_to_opossum(owasp_model: OWASPDependencyReportModel) -> Opossum:
    return Opossum(
        scan_results=ScanResults(
            metadata=_extract_metadata(owasp_model),
            external_attribution_sources=_set_external_attribution_sources(),
            resources=_extract_resources(owasp_model),
        )
    )


def _extract_resources(
    owasp_model: OWASPDependencyReportModel,
) -> RootResource:
    resources = RootResource()
    for dependency in owasp_model.dependencies:
        resource = Resource(
            path=PurePath(dependency.file_path),
            attributions=_get_attribution_info(dependency),
            type=ResourceType.FILE,
        )
        resources.add_resource(resource)

    return resources


def _get_attribution_info(dependency: DependencyModel) -> list[OpossumPackage]:
    package = OpossumPackage(
        source=SourceInfo(document_confidence=50, name="Dependency Check"),
        attribution_confidence=50,
    )
    return [package]


def _extract_metadata(owasp_model: OWASPDependencyReportModel) -> Metadata:
    return Metadata(
        build_date=datetime.datetime.now().isoformat(),
        project_id=owasp_model.project_info.artifact_i_d or str(uuid.uuid4()),
        project_title=owasp_model.project_info.name,
        file_creation_date=owasp_model.project_info.report_date,
    )


def _set_external_attribution_sources() -> dict[str, ExternalAttributionSource]:
    # copied from the haskell variant
    return {
        "Dependency-Check": ExternalAttributionSource(
            name="Dependency-Check", priority=40
        ),
    }
