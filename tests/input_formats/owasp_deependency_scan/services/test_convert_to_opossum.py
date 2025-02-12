# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

from opossum_lib.core.entities.external_attribution_source import (
    ExternalAttributionSource,
)
from opossum_lib.core.entities.metadata import Metadata
from opossum_lib.core.entities.opossum import Opossum
from opossum_lib.core.entities.opossum_package import OpossumPackage
from opossum_lib.core.entities.root_resource import RootResource
from opossum_lib.core.entities.source_info import SourceInfo
from opossum_lib.input_formats.owasp_deependency_scan.entities.owasp_dependency_report_model import (  # noqa: E501
    EvidenceCollectedModel,
    ProjectInfoModel,
)
from opossum_lib.input_formats.owasp_deependency_scan.services.convert_to_opossum import (  # noqa: E501
    convert_to_opossum,
)
from tests.setup.owasp_dependency_scan_faker_setup import OwaspFaker


class TestConvertMetadata:
    def test_convert_metadata(self, owasp_faker: OwaspFaker) -> None:
        owasp_model = owasp_faker.owasp_dependency_report_model()
        owasp_project_info: ProjectInfoModel = owasp_model.project_info

        opossum: Opossum = convert_to_opossum(owasp_model)

        metadata: Metadata = opossum.scan_results.metadata

        assert metadata is not None
        assert metadata.project_title == owasp_project_info.name
        assert metadata.file_creation_date == owasp_project_info.report_date
        assert metadata.project_id is not None

    def test_convert_metadata_existing_id_is_copied(
        self, owasp_faker: OwaspFaker
    ) -> None:
        owasp_model = owasp_faker.owasp_dependency_report_model(
            project_info=owasp_faker.project_info_model(artifact_i_d="Some Id")
        )

        opossum: Opossum = convert_to_opossum(owasp_model)

        assert (
            opossum.scan_results.metadata.project_id
            == owasp_model.project_info.artifact_i_d
        )


class TestAttributionExtraction:
    def test_extracts_basic_attribution(self, owasp_faker: OwaspFaker) -> None:
        owasp_model = owasp_faker.owasp_dependency_report_model(
            dependencies=owasp_faker.dependencies(min_number_of_dependencies=1)
        )

        opossum: Opossum = convert_to_opossum(owasp_model)

        assert opossum.scan_results.resources.number_of_children() > 0
        assert self._get_n_attributions(opossum.scan_results.resources) == len(
            owasp_model.dependencies
        )
        for resource in opossum.scan_results.resources.all_resources():
            for attribution in resource.attributions:
                assert attribution.attribution_confidence == 50
                assert attribution.source == SourceInfo(
                    document_confidence=50, name="Dependency Check"
                )

    def test_attribution_info_from_evidence(self, owasp_faker: OwaspFaker) -> None:
        vendor_evidence_model = owasp_faker.evidence_model(type="vendor")
        product_evidence_model = owasp_faker.evidence_model(type="product")
        version_evidence_model = owasp_faker.evidence_model(type="version")
        owasp_model = owasp_faker.owasp_dependency_report_model(
            dependencies=[
                owasp_faker.dependency_model(
                    packages=[],
                    evidence_collected=EvidenceCollectedModel(
                        vendor_evidence=[vendor_evidence_model],
                        product_evidence=[product_evidence_model],
                        version_evidence=[version_evidence_model],
                    ),
                )
            ]
        )

        opossum: Opossum = convert_to_opossum(owasp_model)

        assert self._get_n_attributions(opossum.scan_results.resources) == 1
        opossum_package = self._get_attributions(opossum.scan_results.resources)[0]
        assert opossum_package.package_name == product_evidence_model.value
        assert opossum_package.package_version == version_evidence_model.value
        assert opossum_package.package_namespace == vendor_evidence_model.value

    def test_attribution_info_from_evidence_defaults_to_empty(
        self, owasp_faker: OwaspFaker
    ) -> None:
        owasp_model = owasp_faker.owasp_dependency_report_model(
            dependencies=[
                owasp_faker.dependency_model(
                    packages=[],
                    evidence_collected=EvidenceCollectedModel(
                        vendor_evidence=[],
                        product_evidence=[],
                        version_evidence=[],
                    ),
                )
            ]
        )

        opossum: Opossum = convert_to_opossum(owasp_model)

        assert self._get_n_attributions(opossum.scan_results.resources) == 1
        opossum_package = self._get_attributions(opossum.scan_results.resources)[0]
        assert opossum_package.package_name is None
        assert opossum_package.package_version is None
        assert opossum_package.package_namespace is None

    def _get_n_attributions(self, root_resource: RootResource) -> int:
        return sum(
            len(resource.attributions) for resource in root_resource.all_resources()
        )

    def _get_attributions(self, root_resource: RootResource) -> list[OpossumPackage]:
        return sum(
            [resource.attributions for resource in root_resource.all_resources()], []
        )


def test_no_outfile_created(owasp_faker: OwaspFaker) -> None:
    owasp_model = owasp_faker.owasp_dependency_report_model()

    opossum: Opossum = convert_to_opossum(owasp_model)

    assert opossum.review_results is None


def test_hardcoded_external_attribution_sources(owasp_faker: OwaspFaker) -> None:
    owasp_model = owasp_faker.owasp_dependency_report_model()

    opossum: Opossum = convert_to_opossum(owasp_model)

    assert len(opossum.scan_results.external_attribution_sources) == 1
    assert opossum.scan_results.external_attribution_sources[
        "Dependency-Check"
    ] == ExternalAttributionSource(name="Dependency-Check", priority=40)
