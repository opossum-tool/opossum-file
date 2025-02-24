# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0


from pathlib import PurePath

import pytest

from opossum_lib.core.entities.base_url_for_sources import BaseUrlsForSources
from opossum_lib.core.entities.config import Config
from opossum_lib.core.entities.resource import Resource, ResourceType
from opossum_lib.core.services.merge_opossums import merge_opossums
from tests.setup.opossum_faker_setup import OpossumFaker


class TestMergeOpossumsHighlevel:
    def test_merge_errors_with_empty_list(self) -> None:
        with pytest.raises(RuntimeError):
            merge_opossums([])

    def test_merge_errors_with_single_opossum(
        self, opossum_faker: OpossumFaker
    ) -> None:
        opossum = opossum_faker.opossum()
        with pytest.raises(RuntimeError):
            merge_opossums([opossum])

    def test_successful_merge_with_empty_review_results(
        self, opossum_faker: OpossumFaker
    ) -> None:
        empty_review_results = opossum_faker.output_file(
            manual_attributions={},
            resolved_external_attributions=[],
            resources_to_attributions={},
        )
        opossum1 = opossum_faker.opossum(
            review_results=empty_review_results.model_copy()
        )
        opossum2 = opossum_faker.opossum(
            review_results=empty_review_results.model_copy()
        )
        opossum3 = opossum_faker.opossum(
            review_results=empty_review_results.model_copy()
        )
        merged = merge_opossums([opossum1, opossum2, opossum3])
        assert merged.review_results is None

    def test_successful_merge_with_single_review_results(
        self, opossum_faker: OpossumFaker
    ) -> None:
        opossum1 = opossum_faker.opossum(generate_review_results=True)
        opossum2 = opossum_faker.opossum(generate_review_results=False)
        opossum3 = opossum_faker.opossum(generate_review_results=False)
        merged = merge_opossums([opossum1, opossum2, opossum3])

        expected = opossum1.review_results
        result = merged.review_results
        assert expected  # assert to reassure type-checker
        assert result

        # Compare all fields except metadata because there the UUID changes
        assert result.manual_attributions == expected.manual_attributions
        assert (
            result.resolved_external_attributions
            == expected.resolved_external_attributions
        )
        assert result.resources_to_attributions == expected.resources_to_attributions

    def test_merge_errors_with_multiple_review_results(
        self, opossum_faker: OpossumFaker
    ) -> None:
        opossum1 = opossum_faker.opossum(generate_review_results=True)
        opossum2 = opossum_faker.opossum(generate_review_results=True)
        with pytest.raises(RuntimeError):
            merge_opossums([opossum1, opossum2])


class TestMergeOpossumsProducesCorrectContent:
    def test_merge_combines_attribution_breakpoints_correctly(
        self, opossum_faker: OpossumFaker
    ) -> None:
        breakpoints1 = opossum_faker.attribution_breakpoints()
        breakpoints2 = opossum_faker.attribution_breakpoints()
        opossum1 = opossum_faker.opossum(
            scan_results=opossum_faker.scan_results(
                attribution_breakpoints=breakpoints1,
            ),
            generate_review_results=False,
        )
        opossum2 = opossum_faker.opossum(
            scan_results=opossum_faker.scan_results(
                attribution_breakpoints=breakpoints2
            )
        )

        merged = merge_opossums([opossum1, opossum2])
        expected = set(breakpoints1 + breakpoints2)
        assert set(merged.scan_results.attribution_breakpoints) == expected

    def test_merge_combines_external_attribution_sources_correctly(
        self, opossum_faker: OpossumFaker
    ) -> None:
        sources1 = {
            "external1": opossum_faker.external_attribution_source(),
            "external2": opossum_faker.external_attribution_source(),
        }
        sources2 = {
            "external1": opossum_faker.external_attribution_source(),
            "external3": opossum_faker.external_attribution_source(),
        }
        opossum1 = opossum_faker.opossum(
            scan_results=opossum_faker.scan_results(
                external_attribution_sources=sources1,
            ),
            generate_review_results=False,
        )
        opossum2 = opossum_faker.opossum(
            scan_results=opossum_faker.scan_results(
                external_attribution_sources=sources2
            )
        )

        merged = merge_opossums([opossum1, opossum2])
        expected = {
            "external1": sources2["external1"],
            "external2": sources1["external2"],
            "external3": sources2["external3"],
        }
        assert merged.scan_results.external_attribution_sources == expected

    def test_merge_combines_frequent_licenses_correctly(
        self, opossum_faker: OpossumFaker
    ) -> None:
        licenses1 = [opossum_faker.frequent_license(), opossum_faker.frequent_license()]
        licenses2 = [opossum_faker.frequent_license()]
        opossum1 = opossum_faker.opossum(
            scan_results=opossum_faker.scan_results(frequent_licenses=licenses1),
            generate_review_results=False,
        )
        opossum2 = opossum_faker.opossum(
            scan_results=opossum_faker.scan_results(frequent_licenses=licenses2)
        )

        merged = merge_opossums([opossum1, opossum2])
        expected = set(licenses1 + licenses2)
        assert set(merged.scan_results.frequent_licenses) == expected

    def test_merge_combines_files_with_children_correctly(
        self, opossum_faker: OpossumFaker
    ) -> None:
        files1 = [
            "a/path/to/a/file",
            "/another/path/to/some/other/file",
            "repeated/path",
        ]
        files2 = ["third/file", "repeated/path"]
        opossum1 = opossum_faker.opossum(
            scan_results=opossum_faker.scan_results(files_with_children=files1),
            generate_review_results=False,
        )
        opossum2 = opossum_faker.opossum(
            scan_results=opossum_faker.scan_results(files_with_children=files2)
        )

        merged = merge_opossums([opossum1, opossum2])
        expected = set(files1 + files2)
        assert set(merged.scan_results.files_with_children) == expected

    def test_merge_combines_base_urls_for_sources_correctly(
        self, opossum_faker: OpossumFaker
    ) -> None:
        base_urls1 = BaseUrlsForSources(url1="url1.com", url2="url2.com")
        base_urls2 = BaseUrlsForSources(url3="url3.com")
        opossum1 = opossum_faker.opossum(
            scan_results=opossum_faker.scan_results(base_urls_for_sources=base_urls1),
            generate_review_results=False,
        )
        opossum2 = opossum_faker.opossum(
            scan_results=opossum_faker.scan_results(base_urls_for_sources=base_urls2)
        )
        merged = merge_opossums([opossum1, opossum2])
        expected = {f"url{i}": f"url{i}.com" for i in [1, 2, 3]}
        assert merged.scan_results.base_urls_for_sources.model_extra == expected

    def test_merge_combines_configs_correctly(
        self, opossum_faker: OpossumFaker
    ) -> None:
        config1 = Config(classifications={0: "this is fine", 1: "This is not fine!"})
        config2 = Config(something_else="Imaginary config")
        opossum1 = opossum_faker.opossum(
            scan_results=opossum_faker.scan_results(config=config1),
            generate_review_results=False,
        )
        opossum2 = opossum_faker.opossum(
            scan_results=opossum_faker.scan_results(config=config2)
        )
        merged = merge_opossums([opossum1, opossum2])
        assert merged.scan_results.config.model_extra
        assert merged.scan_results.config.classifications
        assert "something_else" in merged.scan_results.config.model_extra
        assert merged.scan_results.config.classifications == {
            0: "this is fine",
            1: "This is not fine!",
        }
        assert (
            merged.scan_results.config.model_extra["something_else"]
            == "Imaginary config"
        )

    def test_merge_combines_attribution_to_id_correctly(
        self, opossum_faker: OpossumFaker
    ) -> None:
        packages = [opossum_faker.package() for _ in range(3)]
        attributions_to_id1 = {packages[0]: "0", packages[1]: "1"}
        attributions_to_id2 = {packages[0]: "2", packages[2]: "3"}
        opossum1 = opossum_faker.opossum(
            scan_results=opossum_faker.scan_results(
                attribution_to_id=attributions_to_id1
            ),
            generate_review_results=False,
        )
        opossum2 = opossum_faker.opossum(
            scan_results=opossum_faker.scan_results(
                attribution_to_id=attributions_to_id2
            )
        )

        merged = merge_opossums([opossum1, opossum2])
        expected = {packages[0]: "2", packages[1]: "1", packages[2]: "3"}
        assert merged.scan_results.attribution_to_id == expected

    def test_merge_combines_attributions_correctly(
        self, opossum_faker: OpossumFaker
    ) -> None:
        attributions1 = [opossum_faker.package()]
        attributions2 = [opossum_faker.package(), opossum_faker.package()]

        files1 = opossum_faker.resource_tree()
        my_special_file1 = opossum_faker.resource(
            PurePath("folder/file.txt"),
            attributions=attributions1,
            children={},
            type=ResourceType.FILE,
        )
        files1.add_resource(my_special_file1)

        files2 = opossum_faker.resource_tree()
        my_special_file2 = opossum_faker.resource(
            PurePath("folder/file.txt"),
            attributions=attributions2,
            children={},
            type=ResourceType.FILE,
        )
        files2.add_resource(my_special_file2)

        opossum1 = opossum_faker.opossum(
            generate_review_results=False,
            scan_results=opossum_faker.scan_results(resources=files1),
        )
        opossum2 = opossum_faker.opossum(
            generate_review_results=False,
            scan_results=opossum_faker.scan_results(resources=files2),
        )

        merged = merge_opossums([opossum1, opossum2])
        merged_file_tree = Resource(path=PurePath(""))
        for resource in merged.scan_results.resources.all_resources():
            merged_file_tree.add_resource(resource)

        assert "folder" in merged_file_tree.children
        my_folder_merged = merged_file_tree.children["folder"]
        assert "file.txt" in my_folder_merged.children
        my_special_file_merged = my_folder_merged.children["file.txt"]

        assert my_special_file_merged.path == PurePath("folder/file.txt")
        assert my_special_file_merged.type == ResourceType.FILE
        expected_attributions = set(attributions1) | set(attributions2)
        assert set(my_special_file_merged.attributions) == expected_attributions
        assert my_special_file_merged.children == {}
