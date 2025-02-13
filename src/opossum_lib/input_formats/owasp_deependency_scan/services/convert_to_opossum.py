# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
import datetime
import uuid
from pathlib import PurePath

from packageurl import PackageURL

from opossum_lib.core.entities.external_attribution_source import (
    ExternalAttributionSource,
)
from opossum_lib.core.entities.metadata import Metadata
from opossum_lib.core.entities.opossum import Opossum
from opossum_lib.core.entities.opossum_package import (
    OpossumPackage,
    OpossumPackageBuilder,
)
from opossum_lib.core.entities.resource import Resource, ResourceType
from opossum_lib.core.entities.root_resource import RootResource
from opossum_lib.core.entities.scan_results import ScanResults
from opossum_lib.core.entities.source_info import SourceInfo
from opossum_lib.input_formats.owasp_deependency_scan.entities.owasp_dependency_report_model import (  # noqa: E501
    DependencyModel,
    EvidenceModel,
    OWASPDependencyReportModel,
    PackageModel,
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


def _get_first_evidence_value_or_none(evidences: list[EvidenceModel]) -> str | None:
    if evidences:
        return evidences[0].value
    else:
        return None


def _get_base_builder() -> OpossumPackageBuilder:
    return (OpossumPackageBuilder(SourceInfo(document_confidence=50,
                                            name="Dependency Check"))
        .with_attribution_confidence(50))


def _get_attribution_info_from_package(package: PackageModel) -> OpossumPackageBuilder:
    try:
        purl = PackageURL.from_string(package.id)
        return (_get_base_builder()
                .with_package_version(purl.version)
                .with_package_namespace(purl.namespace)
                .with_package_name(purl.name)
                .with_url(package.url))

    except ValueError:
        return (_get_base_builder()
         .with_package_name(package.id)
         .with_url(package.url))


def _get_builders_from_additional_information(
        dependency: DependencyModel) -> list[OpossumPackageBuilder]:
    if dependency.packages:
        return _get_attribution_builders_from_packages(dependency)
    else:
        return _get_attribution_builders_from_evidence(dependency)


def _get_attribution_builders_from_evidence(dependency):
    evidence_collected = dependency.evidence_collected
    namespace = _get_first_evidence_value_or_none(
        evidence_collected.vendor_evidence
    )
    name = _get_first_evidence_value_or_none(evidence_collected.product_evidence)
    version = _get_first_evidence_value_or_none(evidence_collected.version_evidence)
    return [
        _get_base_builder()
        .with_package_version(version)
        .with_package_namespace(namespace)
        .with_package_name(name)
    ]


def _get_attribution_builders_from_packages(dependency):
    result = []
    for package in dependency.packages:
        result.append(_get_attribution_info_from_package(package))
    return result

def _populate_common_information(
        opossum_package_builder: OpossumPackageBuilder) -> OpossumPackageBuilder:
    return opossum_package_builder


def _get_attribution_info(dependency: DependencyModel) -> list[OpossumPackage]:
    return [_populate_common_information(builder).build() for builder
            in _get_builders_from_additional_information(dependency)]


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
