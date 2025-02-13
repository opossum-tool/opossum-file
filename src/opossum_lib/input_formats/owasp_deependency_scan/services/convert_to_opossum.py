# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
import datetime
import uuid
from pathlib import PurePath
from typing import Literal

from packageurl import PackageURL
from pydantic import RootModel

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
    EvidenceCollectedModel,
    EvidenceModel,
    OWASPDependencyReportModel,
    PackageModel,
    VulnerabilityModel,
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


def _get_base_opossum_package_builder() -> OpossumPackageBuilder:
    return OpossumPackageBuilder(
        SourceInfo(document_confidence=50, name="Dependency Check")
    ).with_attribution_confidence(50)


def _get_attribution_info_from_package(package: PackageModel) -> OpossumPackageBuilder:
    try:
        purl = PackageURL.from_string(package.id)
        return (
            _get_base_opossum_package_builder()
            .with_package_version(purl.version)
            .with_package_namespace(purl.namespace)
            .with_package_name(purl.name)
            .with_url(package.url)
        )

    except ValueError:
        return (
            _get_base_opossum_package_builder()
            .with_package_name(package.id)
            .with_url(package.url)
        )


def _get_builders_from_additional_information(
    dependency: DependencyModel,
) -> list[OpossumPackageBuilder]:
    if dependency.packages:
        return _get_attribution_builders_from_packages(dependency.packages)
    else:
        return _get_attribution_builders_from_evidence(dependency.evidence_collected)


def _get_attribution_builders_from_evidence(
    evidence_collected: EvidenceCollectedModel,
) -> list[OpossumPackageBuilder]:
    namespace = _get_first_evidence_value_or_none(evidence_collected.vendor_evidence)
    name = _get_first_evidence_value_or_none(evidence_collected.product_evidence)
    version = _get_first_evidence_value_or_none(evidence_collected.version_evidence)
    return [
        _get_base_opossum_package_builder()
        .with_package_version(version)
        .with_package_namespace(namespace)
        .with_package_name(name)
    ]


def _get_attribution_builders_from_packages(
    packages: list[PackageModel],
) -> list[OpossumPackageBuilder]:
    result = []
    for package in packages:
        result.append(_get_attribution_info_from_package(package))
    return result


def _extract_comment(dependency: DependencyModel) -> str | None:
    if dependency.vulnerabilities:
        Vulnerabilities = RootModel[list[VulnerabilityModel]]  # noqa: N806
        vulnerabilities = Vulnerabilities(dependency.vulnerabilities)
        return vulnerabilities.model_dump_json(indent=4, exclude_none=True)
    else:
        return None


def _populate_common_information(
    opossum_package_builder: OpossumPackageBuilder,
    dependency: DependencyModel,
) -> OpossumPackageBuilder:
    return opossum_package_builder.with_follow_up(
        _extract_follow_up(dependency)
    ).with_comment(_extract_comment(dependency))


def _extract_follow_up(dependency: DependencyModel) -> Literal["FOLLOW_UP"] | None:
    if dependency.vulnerabilities:
        return "FOLLOW_UP"
    else:
        return None


def _get_attribution_info(dependency: DependencyModel) -> list[OpossumPackage]:
    return [
        _populate_common_information(builder, dependency).build()
        for builder in _get_builders_from_additional_information(dependency)
    ]


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
