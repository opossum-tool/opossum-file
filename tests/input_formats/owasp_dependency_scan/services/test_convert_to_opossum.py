# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
import json

from packageurl import PackageURL

from opossum_lib.core.entities.external_attribution_source import (
    ExternalAttributionSource,
)
from opossum_lib.core.entities.metadata import Metadata
from opossum_lib.core.entities.opossum import Opossum
from opossum_lib.core.entities.opossum_package import OpossumPackage
from opossum_lib.core.entities.resource import Resource
from opossum_lib.core.entities.root_resource import RootResource
from opossum_lib.core.entities.source_info import SourceInfo
from opossum_lib.input_formats.owasp_dependency_scan.entities.owasp_dependency_report_model import (  # noqa: E501
    EvidenceCollectedModel,
    ProjectInfoModel,
)
from opossum_lib.input_formats.owasp_dependency_scan.services.convert_to_opossum import (  # noqa: E501
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
            project_info=owasp_faker.project_info_model(
                artifact_i_d=str(owasp_faker.uuid4())
            )
        )

        opossum: Opossum = convert_to_opossum(owasp_model)

        assert (
            opossum.scan_results.metadata.project_id
            == owasp_model.project_info.artifact_i_d
        )


class TestAttributionExtraction:
    def test_extracts_basic_attribution(self, owasp_faker: OwaspFaker) -> None:
        valid_dependency = owasp_faker.dependency_model(
            packages=owasp_faker.package_models(min_nb_of_packages=1),
        )
        owasp_model = owasp_faker.owasp_dependency_report_model(
            dependencies=owasp_faker.dependencies() + [valid_dependency]
        )

        opossum: Opossum = convert_to_opossum(owasp_model)

        assert len(list(opossum.scan_results.resources.all_resources())) > 0
        assert self._get_number_of_attributions(opossum.scan_results.resources) >= len(
            owasp_model.dependencies
        )
        self._assert_constant_parameters_are_set_on_all_attributions(opossum)

    def _assert_constant_parameters_are_set_on_all_attributions(
        self, opossum: Opossum
    ) -> None:
        for resource in opossum.scan_results.resources.all_resources():
            for attribution in resource.attributions:
                assert attribution.attribution_confidence == 50
                assert attribution.source == SourceInfo(
                    document_confidence=50, name="Dependency-Check"
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

        assert self._get_number_of_attributions(opossum.scan_results.resources) == 1
        opossum_package = self._get_attributions(opossum.scan_results.resources)[0]
        assert opossum_package.package_name == product_evidence_model.value
        assert opossum_package.package_version == version_evidence_model.value
        assert opossum_package.package_namespace == vendor_evidence_model.value

    def test_no_package_and_no_evidences_produce_no_attribution(
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

        assert self._get_number_of_attributions(opossum.scan_results.resources) == 0

    def test_attribution_from_packages(self, owasp_faker: OwaspFaker) -> None:
        package = owasp_faker.package_model()
        owasp_model = owasp_faker.owasp_dependency_report_model(
            dependencies=[
                owasp_faker.dependency_model(
                    packages=[package],
                )
            ]
        )

        opossum: Opossum = convert_to_opossum(owasp_model)

        assert self._get_number_of_attributions(opossum.scan_results.resources) == 1
        opossum_package = self._get_attributions(opossum.scan_results.resources)[0]
        purl = PackageURL.from_string(package.id)
        assert opossum_package.package_name == purl.name
        assert opossum_package.package_version == purl.version
        assert opossum_package.package_namespace == purl.namespace
        assert opossum_package.url == package.url
        assert opossum_package.package_type == purl.type

    def test_attribution_from_non_purl_packages(self, owasp_faker: OwaspFaker) -> None:
        package = owasp_faker.package_model(id="foobar")
        owasp_model = owasp_faker.owasp_dependency_report_model(
            dependencies=[
                owasp_faker.dependency_model(
                    packages=[package],
                )
            ]
        )

        opossum: Opossum = convert_to_opossum(owasp_model)

        assert self._get_number_of_attributions(opossum.scan_results.resources) == 1
        opossum_package = self._get_attributions(opossum.scan_results.resources)[0]
        assert opossum_package.package_name == "foobar"
        assert opossum_package.url == package.url

    def test_attribution_with_vulnerabilities_needs_follow_up_and_comment(
        self, owasp_faker: OwaspFaker
    ) -> None:
        vulnerability = owasp_faker.vulnerability_model()
        owasp_model = owasp_faker.owasp_dependency_report_model(
            dependencies=[
                owasp_faker.dependency_model(
                    vulnerabilities=[vulnerability],
                    packages=owasp_faker.package_models(min_nb_of_packages=1),
                )
            ]
        )

        opossum: Opossum = convert_to_opossum(owasp_model)

        assert self._get_number_of_attributions(opossum.scan_results.resources) >= 1
        for opossum_package in self._get_attributions(opossum.scan_results.resources):
            assert opossum_package.follow_up == "FOLLOW_UP"
            assert opossum_package.comment is not None
            assert json.loads(opossum_package.comment) == json.loads(
                "[" + vulnerability.model_dump_json(indent=4, exclude_none=True) + "]"
            )

    def test_attribution_without_vulnerabilities_no_follow_up_no_comment(
        self, owasp_faker: OwaspFaker
    ) -> None:
        owasp_model = owasp_faker.owasp_dependency_report_model(
            dependencies=[
                owasp_faker.dependency_model(
                    vulnerabilities=[],
                    packages=owasp_faker.package_models(min_nb_of_packages=1),
                )
            ]
        )

        opossum: Opossum = convert_to_opossum(owasp_model)

        assert self._get_number_of_attributions(opossum.scan_results.resources) >= 1
        for opossum_package in self._get_attributions(opossum.scan_results.resources):
            assert opossum_package.follow_up is None
            assert opossum_package.comment is None

    def test_get_attribution_populates_license_if_present(
        self, owasp_faker: OwaspFaker
    ) -> None:
        license_text = owasp_faker.word()
        owasp_model = owasp_faker.owasp_dependency_report_model(
            dependencies=[
                owasp_faker.dependency_model(
                    license=license_text,
                    packages=owasp_faker.package_models(min_nb_of_packages=1),
                )
            ]
        )

        opossum: Opossum = convert_to_opossum(owasp_model)

        assert self._get_number_of_attributions(opossum.scan_results.resources) >= 1
        for opossum_package in self._get_attributions(opossum.scan_results.resources):
            assert opossum_package.license_name == license_text

    def _get_number_of_attributions(self, root_resource: RootResource) -> int:
        return sum(
            len(resource.attributions) for resource in root_resource.all_resources()
        )

    def _get_attributions(self, root_resource: RootResource) -> list[OpossumPackage]:
        return sum(
            [resource.attributions for resource in root_resource.all_resources()], []
        )


class TestResourceGeneration:
    def test_non_virtual_dependencies_path_from_dependency(
        self, owasp_faker: OwaspFaker
    ) -> None:
        dependency = owasp_faker.dependency_model(is_virtual=False)
        owasp_model = owasp_faker.owasp_dependency_report_model(
            dependencies=[dependency]
        )

        opossum: Opossum = convert_to_opossum(owasp_model)

        assert (
            self._get_path_of_leaf_resource(opossum.scan_results.resources)
        ) == dependency.file_path

    def test_virtual_dependency_path_from_dependency_path_and_name(
        self, owasp_faker: OwaspFaker
    ) -> None:
        dependency = owasp_faker.dependency_model(is_virtual=True)
        owasp_model = owasp_faker.owasp_dependency_report_model(
            dependencies=[dependency]
        )

        opossum: Opossum = convert_to_opossum(owasp_model)

        assert (
            self._get_path_of_leaf_resource(opossum.scan_results.resources)
        ) == dependency.file_path + "/" + dependency.file_name

    def _get_path_of_leaf_resource(self, root_resource: RootResource) -> str:
        assert len(root_resource.children) == 1
        start_path = list(root_resource.children.keys())[0]

        def _get_remaining_path(resource: Resource) -> str:
            if len(resource.children) == 0:
                return ""
            else:
                assert len(resource.children) == 1
                additional_path = list(resource.children.keys())[0]
                return (
                    "/"
                    + additional_path
                    + _get_remaining_path(resource.children[additional_path])
                )

        return (
            "/" + start_path + _get_remaining_path(root_resource.children[start_path])
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


def test_each_virtual_dependency_creates_a_file_with_children(
    owasp_faker: OwaspFaker,
) -> None:
    virtual_dependency = owasp_faker.dependency_model(is_virtual=True)
    owasp_model = owasp_faker.owasp_dependency_report_model(
        dependencies=[
            virtual_dependency,
            owasp_faker.dependency_model(is_virtual=False),
        ]
    )

    print(owasp_model)

    opossum: Opossum = convert_to_opossum(owasp_model)

    assert opossum.scan_results.files_with_children == [
        virtual_dependency.file_path + "/"
    ]
