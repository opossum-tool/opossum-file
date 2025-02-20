# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0


import pytest

from opossum_lib.core.entities.opossum import Opossum
from opossum_lib.core.entities.resource import Resource, ResourceType
from opossum_lib.input_formats.scancode.constants import (
    SCANCODE_SOURCE_NAME,
    SCANCODE_SOURCE_NAME_DEPENDENCY,
    SCANCODE_SOURCE_NAME_PACKAGE,
)
from opossum_lib.input_formats.scancode.services.convert_to_opossum import (
    convert_to_opossum,
)
from opossum_lib.shared.entities.opossum_input_file_model import (
    OpossumPackageModel,
    SourceInfoModel,
)
from tests.setup.scancode_faker_setup import ScanCodeFaker


class TestExtractScancodeHeader:
    def test_produces_expected_result(
        self,
        scancode_faker: ScanCodeFaker,
    ) -> None:
        scancode_data = scancode_faker.scancode_data()
        opossum = convert_to_opossum(scancode_data)
        metadata = opossum.scan_results.metadata
        header = scancode_data.headers[0]
        assert metadata.file_creation_date == header.end_timestamp
        assert metadata.project_title == "ScanCode file"

    def test_errors_with_missing_header(self, scancode_faker: ScanCodeFaker) -> None:
        scancode_data = scancode_faker.scancode_data(headers=[])

        with pytest.raises(RuntimeError):
            convert_to_opossum(scancode_data)

    def test_errors_with_multiple_headers(self, scancode_faker: ScanCodeFaker) -> None:
        header1 = scancode_faker.header()
        header2 = scancode_faker.header()
        scancode_data = scancode_faker.scancode_data(headers=[header1, header2])

        with pytest.raises(RuntimeError):
            convert_to_opossum(scancode_data)


class TestScancodeIndividualOptions:
    def test_full_root_path_option_gives_identical_result(
        self, scancode_faker: ScanCodeFaker
    ) -> None:
        options_default = scancode_faker.options(full_root=False, strip_root=False)
        options_full_root = options_default.model_copy(update={"full_root": True})
        pathtree = scancode_faker.generate_path_structure()

        seed = scancode_faker.random_int()
        scancode_faker.seed_instance(seed)
        files_default = scancode_faker.files(
            path_tree=pathtree, options=options_default
        )
        scancode_faker.seed_instance(seed)
        files_full_root = scancode_faker.files(
            path_tree=pathtree, options=options_full_root
        )

        scancode_data_default = scancode_faker.scancode_data(
            files=files_default, options=options_default
        )
        scancode_data_full_root = scancode_faker.scancode_data(
            files=files_full_root, options=options_full_root
        )

        opossum_default = convert_to_opossum(scancode_data_default)
        opossum_full_root = convert_to_opossum(scancode_data_full_root)

        assert (
            opossum_default.scan_results.resources
            == opossum_full_root.scan_results.resources
        )

    def test_strip_root_path_option_gives_identical_result(
        self, scancode_faker: ScanCodeFaker
    ) -> None:
        options_default = scancode_faker.options(full_root=False, strip_root=False)
        options_strip_root = options_default.model_copy(update={"strip_root": True})
        pathtree = scancode_faker.generate_path_structure()

        seed = scancode_faker.random_int()
        scancode_faker.seed_instance(seed)
        files_default = scancode_faker.files(
            path_tree=pathtree, options=options_default
        )
        scancode_faker.seed_instance(seed)
        files_strip_root = scancode_faker.files(
            path_tree=pathtree, options=options_strip_root
        )

        scancode_data_default = scancode_faker.scancode_data(
            files=files_default, options=options_default
        )
        scancode_data_strip_root = scancode_faker.scancode_data(
            files=files_strip_root, options=options_strip_root
        )
        opossum_default = convert_to_opossum(scancode_data_default)
        opossum_strip_root = convert_to_opossum(scancode_data_strip_root)

        assert (
            opossum_default.scan_results.resources
            == opossum_strip_root.scan_results.resources
        )

    def _assert_and_get_single_file(self, opossum: Opossum) -> Resource:
        file = None
        for resource in opossum.scan_results.resources.all_resources():
            assert resource.type is None or resource.type == ResourceType.FILE
            if resource.type == ResourceType.FILE:
                assert file is None
                file = resource
        assert file
        return file

    def test_copyright_is_always_preserved(self, scancode_faker: ScanCodeFaker) -> None:
        options = scancode_faker.options(copyright=True)
        copyright = scancode_faker.copyright(copyright="Foobar company <foo@bar.com>")
        file = scancode_faker.single_file(
            path="file.txt", copyrights=[copyright], options=options
        )
        scancode_data = scancode_faker.scancode_data(options=options, files=[file])

        opossum = convert_to_opossum(scancode_data)
        file_opossum = self._assert_and_get_single_file(opossum)
        all_copyrights = "\n".join(
            attribution.copyright
            for attribution in file_opossum.attributions
            if attribution.copyright
        )
        assert "Foobar company <foo@bar.com>" in all_copyrights

    def test_license_detections_are_converted_to_attributions(
        self, scancode_faker: ScanCodeFaker
    ) -> None:
        options = scancode_faker.options(license=True)
        license_detection1 = scancode_faker.license_detection(
            license_expression_spdx="MIT", path="file.txt"
        )
        license_detection2 = scancode_faker.license_detection(
            license_expression_spdx="CC0", path="file.txt"
        )
        file = scancode_faker.single_file(
            path="file.txt",
            license_detections=[license_detection1, license_detection2],
            options=options,
        )
        scancode_data = scancode_faker.scancode_data(options=options, files=[file])

        opossum = convert_to_opossum(scancode_data)
        file_opossum = self._assert_and_get_single_file(opossum)
        assert len(file_opossum.attributions) >= 2
        all_detected_licenses = {
            attribution.license_name for attribution in file_opossum.attributions
        }
        assert {"MIT", "CC0"}.issubset(all_detected_licenses)

    def test_license_reference_is_used_for_license_text(
        self, scancode_faker: ScanCodeFaker
    ) -> None:
        options = scancode_faker.options(license=True, license_references=True)
        license_reference = scancode_faker.license_reference(
            spdx_license_key="MIT", text="Some where long license text."
        )
        license_detection1 = scancode_faker.license_detection(
            license_expression_spdx="MIT", path="file.txt"
        )
        license_detection2 = scancode_faker.license_detection(
            license_expression_spdx="CC0", path="file.txt"
        )
        file = scancode_faker.single_file(
            path="file.txt",
            license_detections=[license_detection1, license_detection2],
            options=options,
        )
        scancode_data = scancode_faker.scancode_data(
            options=options, files=[file], license_references=[license_reference]
        )

        opossum = convert_to_opossum(scancode_data)
        file_opossum = self._assert_and_get_single_file(opossum)
        assert len(file_opossum.attributions) >= 2
        for attribution in file_opossum.attributions:
            if attribution.license_name == "MIT":
                assert attribution.license_text == "Some where long license text."

    def test_url_data_is_always_preserved(self, scancode_faker: ScanCodeFaker) -> None:
        options = scancode_faker.options(url=True)
        url1 = scancode_faker.sc_url(url="https://www.foo.bar")
        url2 = scancode_faker.sc_url(url="http://www.baz.abc")
        file = scancode_faker.single_file(
            path="file.txt", urls=[url1, url2], options=options
        )
        scancode_data = scancode_faker.scancode_data(options=options, files=[file])

        opossum = convert_to_opossum(scancode_data)
        file_opossum = self._assert_and_get_single_file(opossum)
        all_comments = "\n".join(
            attribution.comment
            for attribution in file_opossum.attributions
            if attribution.comment
        )
        assert "https://www.foo.bar" in all_comments
        assert "http://www.baz.abc" in all_comments

    def test_purl_data_is_always_preserved(self, scancode_faker: ScanCodeFaker) -> None:
        options = scancode_faker.options(package=True)
        purl = "pkg:type/namespace/name@version?qualifiers=whatever#subpath"
        file = scancode_faker.single_file(
            path="file.txt", for_packages=[purl], options=options
        )
        scancode_data = scancode_faker.scancode_data(options=options, files=[file])

        opossum = convert_to_opossum(scancode_data)
        file_opossum = self._assert_and_get_single_file(opossum)
        for attribution in file_opossum.attributions:
            if (
                attribution.package_name == "name"
                and attribution.package_version == "version"
                and attribution.package_namespace == "namespace"
                and attribution.package_type == "type"
                and attribution.package_purl_appendix == "qualifiers=whatever#subpath"
            ):
                break
        else:
            assert (
                file_opossum.attributions
                == "does not contain an attribution with the information of the PURL"
            )

    def test_package_data_is_converted_to_attributions(
        self, scancode_faker: ScanCodeFaker
    ) -> None:
        options = scancode_faker.options(package=True)
        match1 = scancode_faker.match(
            license_expression_spdx="MyLicense", score=50, from_file="file.txt"
        )
        match2 = scancode_faker.match(
            license_expression_spdx="MyLicense", score=75, from_file="file.txt"
        )
        license_detection = scancode_faker.license_detection(
            license_expression_spdx="MyLicense", matches=[match1, match2]
        )
        package_data = scancode_faker.package_data(
            purl="",
            copyright="Myself <I@myself.me>",
            name="My package",
            version="best",
            namespace="universe",
            type="dummy",
            license_detections=[license_detection],
            declared_license_expression_spdx="MyLicense",
            homepage_url="www.some.url",
        )
        file = scancode_faker.single_file(
            path="file.txt",
            package_data=[package_data],
            options=options,
        )
        scancode_data = scancode_faker.scancode_data(options=options, files=[file])

        opossum = convert_to_opossum(scancode_data)
        file_opossum = self._assert_and_get_single_file(opossum)
        for attribution in file_opossum.attributions:
            if attribution.source.name == SCANCODE_SOURCE_NAME_PACKAGE:
                assert attribution.license_name == "MyLicense"
                assert attribution.package_name == "My package"
                assert attribution.package_version == "best"
                assert attribution.package_namespace == "universe"
                assert attribution.package_type == "dummy"
                assert attribution.url == "www.some.url"
                assert attribution.attribution_confidence == 75
                break
        else:
            assert (
                file_opossum.attributions
                == "Does not contain an attribution matching the package data"
            )

    def test_dependency_data_is_converted_to_attributions(
        self, scancode_faker: ScanCodeFaker
    ) -> None:
        options = scancode_faker.options(package=True)
        dependency = scancode_faker.dependency(purl="pkg:dummy/test/dependency1@0.0.0")
        package_data = scancode_faker.package_data(dependencies=[dependency])
        file = scancode_faker.single_file(
            path="file.txt",
            package_data=[package_data],
            options=options,
        )
        scancode_data = scancode_faker.scancode_data(options=options, files=[file])

        opossum = convert_to_opossum(scancode_data)
        file_opossum = self._assert_and_get_single_file(opossum)

        dependency_attributions = [
            attribution
            for attribution in file_opossum.attributions
            if attribution.source.name == SCANCODE_SOURCE_NAME_DEPENDENCY
        ]
        assert len(dependency_attributions) == 1
        attribution = dependency_attributions[0]
        assert attribution.package_name == "dependency1"
        assert attribution.package_version == "0.0.0"
        assert attribution.package_namespace == "test"
        assert attribution.package_type == "dummy"

    def test_license_conversion_produces_expected_result(
        self, scancode_faker: ScanCodeFaker
    ) -> None:
        options = scancode_faker.options(package=False, license=True, input=["A"])
        match1 = scancode_faker.match(
            license_expression_spdx="Apache-2.0",
            from_file="A",
            score=75,
            rule_relevance=50,
        )
        match2 = scancode_faker.match(
            license_expression_spdx="Apache-2.0",
            from_file="A",
            score=95,
            rule_relevance=50,
        )
        match3 = scancode_faker.match(
            license_expression_spdx="MIT",
            from_file="A",
            score=50,
            rule_relevance=50,
        )
        license1 = scancode_faker.license_detection(
            license_expression_spdx="Apache-2.0",
            matches=[match1, match2],
        )
        license2 = scancode_faker.license_detection(
            license_expression_spdx="MIT",
            matches=[match3],
        )
        copyright1 = scancode_faker.copyright(copyright="Me")
        copyright2 = scancode_faker.copyright(copyright="Myself")
        copyright3 = scancode_faker.copyright(copyright="I")
        file = scancode_faker.single_file(
            path="A",
            license_detections=[license1, license2],
            copyrights=[copyright1, copyright2, copyright3],
            options=options,
        )
        scancode_data = scancode_faker.scancode_data(files=[file], options=options)
        opossum = convert_to_opossum(scancode_data)
        attributions = (
            opossum.to_opossum_file_model().input_file.external_attributions.values()
        )

        expected1 = OpossumPackageModel(
            source=SourceInfoModel(name=SCANCODE_SOURCE_NAME, document_confidence=50),
            license_name="MIT",
            copyright="Me\nMyself\nI",
            attribution_confidence=50,
        )
        expected2 = OpossumPackageModel(
            source=SourceInfoModel(name=SCANCODE_SOURCE_NAME, document_confidence=95),
            license_name="Apache-2.0",
            copyright="Me\nMyself\nI",
            attribution_confidence=95,
        )
        assert len(attributions) == 2
        attribution1, attribution2 = sorted(
            attributions, key=lambda attr: attr.attribution_confidence or 0
        )
        assert attribution1.source == expected1.source
        assert attribution1.license_name == expected1.license_name
        assert attribution1.copyright == expected1.copyright
        assert attribution1.attribution_confidence == expected1.attribution_confidence

        assert attribution2.source == expected2.source
        assert attribution2.license_name == expected2.license_name
        assert attribution2.copyright == expected2.copyright
        assert attribution2.attribution_confidence == expected2.attribution_confidence


class TestConvertToOpossumFull:
    def test_convert(
        self,
        scancode_faker: ScanCodeFaker,
    ) -> None:
        scancode_data = scancode_faker.scancode_data()
        opossum = convert_to_opossum(scancode_data)

        assert opossum.review_results is None
        scan_results = opossum.scan_results
        expected_num_resources = len(scancode_data.files)
        assert (
            sum(
                1
                for resource in scan_results.resources.all_resources()
                if resource.type
            )
            == expected_num_resources
        )
        num_attributions = sum(
            len(resource.attributions)
            for resource in scan_results.resources.all_resources()
        )
        num_license_detections = 0
        max_num_of_attributions = 0
        for file in scancode_data.files:
            license_detections = len(file.license_detections or [])
            num_license_detections += license_detections
            max_num_of_attributions += license_detections or 1
            max_num_of_attributions += len(file.package_data or [])
            for package in file.package_data or []:
                max_num_of_attributions += len(package.dependencies or [])
        assert max_num_of_attributions >= num_attributions >= num_license_detections
