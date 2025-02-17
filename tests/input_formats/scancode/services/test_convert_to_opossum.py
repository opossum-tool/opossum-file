# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0


import pytest

from opossum_lib.core.entities.resource import ResourceType
from opossum_lib.input_formats.scancode.constants import (
    SCANCODE_SOURCE_NAME_DEPENDENCY,
    SCANCODE_SOURCE_NAME_PACKAGE,
)
from opossum_lib.input_formats.scancode.services.convert_to_opossum import (
    convert_to_opossum,
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
    def test_path_options_give_identical_results(
        self, scancode_faker: ScanCodeFaker
    ) -> None:
        options_default = scancode_faker.options(
            full_root=False, strip_root=False, license_references=False
        )
        options_full_root = options_default.model_copy(update={"full_root": True})
        options_strip_root = options_default.model_copy(update={"strip_root": True})
        header_default = scancode_faker.header(options=options_default)
        header_full_root = header_default.model_copy(
            update={"options": options_full_root}
        )
        header_strip_root = header_default.model_copy(
            update={"options": options_strip_root}
        )
        pathtree = scancode_faker.generate_path_structure(
            depth=1, max_folders_per_level=1, max_files_per_level=1
        )
        seed = scancode_faker.random_int()
        scancode_faker.seed_instance(seed)
        files_default = scancode_faker.files(
            path_tree=pathtree, options=options_default
        )
        scancode_faker.seed_instance(seed)
        files_full_root = scancode_faker.files(
            path_tree=pathtree, options=options_full_root
        )
        scancode_faker.seed_instance(seed)
        files_strip_root = scancode_faker.files(
            path_tree=pathtree, options=options_strip_root
        )
        scancode_data_default = scancode_faker.scancode_data(
            headers=[header_default], files=files_default
        )
        scancode_data_full_root = scancode_faker.scancode_data(
            headers=[header_full_root], files=files_full_root
        )
        scancode_data_strip_root = scancode_faker.scancode_data(
            headers=[header_strip_root], files=files_strip_root
        )
        opossum_default = convert_to_opossum(scancode_data_default)
        opossum_full_root = convert_to_opossum(scancode_data_full_root)
        opossum_strip_root = convert_to_opossum(scancode_data_strip_root)

        assert (
            opossum_default.scan_results.resources
            == opossum_full_root.scan_results.resources
        )
        assert (
            opossum_default.scan_results.resources
            == opossum_strip_root.scan_results.resources
        )

    def test_copyright_is_always_preserved(self, scancode_faker: ScanCodeFaker) -> None:
        options = scancode_faker.options(copyright=True)
        copyright = scancode_faker.copyright(copyright="Foobar company <foo@bar.com>")
        file = scancode_faker.single_file(
            path="file.txt", copyrights=[copyright], options=options
        )
        scancode_data = scancode_faker.scancode_data(options=options, files=[file])

        opossum = convert_to_opossum(scancode_data)
        opossum_files = list(opossum.scan_results.resources.all_resources())
        assert len(opossum_files) == 2
        assert opossum_files[0].type is None  # automatically generated Root folder
        assert opossum_files[1].type == ResourceType.FILE  # our file
        all_copyrights = "\n".join(
            attribution.copyright
            for attribution in opossum_files[1].attributions
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
        opossum_files = list(opossum.scan_results.resources.all_resources())
        assert len(opossum_files) == 2
        assert opossum_files[0].type is None  # automatically generated Root folder
        assert opossum_files[1].type == ResourceType.FILE  # our file
        assert len(opossum_files[1].attributions) >= 2
        all_detected_licenses = {
            attribution.license_name for attribution in opossum_files[1].attributions
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
        opossum_files = list(opossum.scan_results.resources.all_resources())
        assert len(opossum_files) == 2
        assert opossum_files[0].type is None  # automatically generated Root folder
        assert opossum_files[1].type == ResourceType.FILE  # our file
        assert len(opossum_files[1].attributions) >= 2
        for attribution in opossum_files[1].attributions:
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
        opossum_files = list(opossum.scan_results.resources.all_resources())
        assert len(opossum_files) == 2
        assert opossum_files[0].type is None  # automatically generated Root folder
        assert opossum_files[1].type == ResourceType.FILE  # our file
        all_comments = "\n".join(
            attribution.comment
            for attribution in opossum_files[1].attributions
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
        opossum_files = list(opossum.scan_results.resources.all_resources())
        assert len(opossum_files) == 2
        assert opossum_files[0].type is None  # automatically generated Root folder
        assert opossum_files[1].type == ResourceType.FILE  # our file
        for attribution in opossum_files[1].attributions:
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
                opossum_files[1].attributions
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
        opossum_files = list(opossum.scan_results.resources.all_resources())
        assert len(opossum_files) == 2
        assert opossum_files[0].type is None  # automatically generated Root folder
        assert opossum_files[1].type == ResourceType.FILE  # our file
        for attribution in opossum_files[1].attributions:
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
                opossum_files[1].attributions
                == "Does not contain an attribution matching the package data"
            )

    def test_dependency_data_is_converted_to_attributions(
        self, scancode_faker: ScanCodeFaker
    ) -> None:
        options = scancode_faker.options(package=True)
        dependency1 = scancode_faker.dependency(purl="pkg:dummy/test/dependency1@0.0.0")
        dependency2 = scancode_faker.dependency(purl="pkg:dummy/test/dependency2@42")
        # pkg:type/namespace/name@version?qualifiers=whatever#subpath
        package_data = scancode_faker.package_data(
            dependencies=[dependency1, dependency2]
        )
        file = scancode_faker.single_file(
            path="file.txt",
            package_data=[package_data],
            options=options,
        )
        scancode_data = scancode_faker.scancode_data(options=options, files=[file])

        opossum = convert_to_opossum(scancode_data)
        opossum_files = list(opossum.scan_results.resources.all_resources())
        assert len(opossum_files) == 2
        assert opossum_files[0].type is None  # automatically generated Root folder
        assert opossum_files[1].type == ResourceType.FILE  # our file
        dependency_attributions = [
            attribution
            for attribution in opossum_files[1].attributions
            if attribution.source.name == SCANCODE_SOURCE_NAME_DEPENDENCY
        ]
        assert len(dependency_attributions) == 2
        dep1, dep2 = sorted(
            dependency_attributions, key=lambda attr: attr.package_version or ""
        )

        assert dep1.package_name == "dependency1"
        assert dep1.package_version == "0.0.0"
        assert dep1.package_namespace == "test"
        assert dep1.package_type == "dummy"

        assert dep2.package_name == "dependency2"
        assert dep2.package_version == "42"
        assert dep2.package_namespace == "test"
        assert dep2.package_type == "dummy"


class TestConvertToOpossumFull:
    def test_convert(
        self,
        scancode_faker: ScanCodeFaker,
    ) -> None:
        scancode_data = scancode_faker.scancode_data()
        opossum = convert_to_opossum(scancode_data)

        assert opossum.review_results is None
        scan_results = opossum.scan_results
        assert (
            len(list(scan_results.resources.all_resources()))
            == len(scancode_data.files) + 1
        )  # +1 for the root folder
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
