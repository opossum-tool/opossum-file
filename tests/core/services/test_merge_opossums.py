# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0


from pathlib import PurePath

import pytest

from opossum_lib.core.entities.resource import Resource, ResourceType
from opossum_lib.core.services.merge_opossums import merge_opossums
from tests.setup.opossum_faker_setup import OpossumFaker


class TestMergeOpossumFiles:
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
            scan_results=opossum_faker.scan_results(resources=[files1]),
        )
        opossum2 = opossum_faker.opossum(
            generate_review_results=False,
            scan_results=opossum_faker.scan_results(resources=[files2]),
        )

        merged = merge_opossums([opossum1, opossum2])
        merged_file_tree = Resource(path=PurePath(""))
        for resource in merged.scan_results.resources:
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

    def test_merge_errors_with_multiple_review_results(
        self, opossum_faker: OpossumFaker
    ) -> None:
        opossum1 = opossum_faker.opossum(generate_review_results=True)
        opossum2 = opossum_faker.opossum(generate_review_results=True)
        with pytest.raises(RuntimeError):
            merge_opossums([opossum1, opossum2])
