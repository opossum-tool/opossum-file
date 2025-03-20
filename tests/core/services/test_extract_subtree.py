# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

from pathlib import PurePath

from opossum_lib.core.entities.resource import Resource, ResourceType
from opossum_lib.core.services.extract_subtree_impl import extract_subtree_impl
from tests.setup.opossum_faker_setup import OpossumFaker


class TestExtractSubtreeHighlevel:
    def test_extraction_is_generally_successful_without_review_results(
        self, opossum_faker: OpossumFaker
    ) -> None:
        opossum = opossum_faker.opossum(generate_review_results=False)
        all_folders = [
            resource.path
            for resource in opossum.scan_results.resources.all_resources()
            if resource.type == ResourceType.FOLDER
        ]
        subpath = (
            opossum_faker.random_element(all_folders) if all_folders else PurePath("")
        )
        extracted = extract_subtree_impl(opossum, subpath)

        assert extracted
        assert extracted.review_results is None
        assert extracted.scan_results
        if opossum.scan_results.resources.children:
            assert extracted.scan_results.resources.children

    def test_extraction_is_generally_successful_including_review_results(
        self, opossum_faker: OpossumFaker
    ) -> None:
        opossum = opossum_faker.opossum(generate_review_results=True)
        all_folders = [
            resource.path
            for resource in opossum.scan_results.resources.all_resources()
            if resource.type == ResourceType.FOLDER
        ]
        subpath = (
            opossum_faker.random_element(all_folders) if all_folders else PurePath("")
        )
        extracted = extract_subtree_impl(opossum, subpath)

        assert extracted
        assert extracted.review_results
        assert extracted.scan_results
        if opossum.scan_results.resources.children:
            assert extracted.scan_results.resources.children


class TestExtractSubTreeAttributes:
    SUBTREE = PurePath("toplevel/folder")

    def _get_test_resources(self, opossum_faker: OpossumFaker) -> list[Resource]:
        return [
            opossum_faker.resource(
                path=PurePath("toplevel/resource1.txt"), type=ResourceType.FILE
            ),
            opossum_faker.resource(
                path=PurePath("toplevel/folder"), type=ResourceType.FOLDER
            ),
            opossum_faker.resource(
                path=PurePath("toplevel/folder/resource2"), type=ResourceType.FILE
            ),
            opossum_faker.resource(
                path=PurePath("toplevel/folder/resource3"), type=ResourceType.FILE
            ),
        ]

    def test_extraction_is_extracts_correct_resources(
        self, opossum_faker: OpossumFaker
    ) -> None:
        resources = self._get_test_resources(opossum_faker)
        scan_results = opossum_faker.scan_results(resources=resources)
        opossum = opossum_faker.opossum(scan_results=scan_results)

        extracted = extract_subtree_impl(opossum, TestExtractSubTreeAttributes.SUBTREE)
        extracted_root_resource = extracted.scan_results.resources
        extracted_paths = [
            str(resource.path) for resource in extracted_root_resource.all_resources()
        ]
        extracted_attributions = {
            attribution
            for resource in extracted_root_resource.all_resources()
            for attribution in resource.attributions
        }

        assert set(extracted_paths) == {
            "folder",
            "folder/resource2",
            "folder/resource3",
        }

        expected_attributions = {
            attribution
            for resource in resources[1:]
            for attribution in resource.attributions
        }
        assert expected_attributions == extracted_attributions

    def test_extraction_is_filters_attribution_to_ids(
        self, opossum_faker: OpossumFaker
    ) -> None:
        resources = self._get_test_resources(opossum_faker)
        scan_results = opossum_faker.scan_results(resources=resources)
        opossum = opossum_faker.opossum(scan_results=scan_results)

        extracted = extract_subtree_impl(opossum, TestExtractSubTreeAttributes.SUBTREE)
        extracted_root_resource = extracted.scan_results.resources
        extracted_attributions = {
            attribution
            for resource in extracted_root_resource.all_resources()
            for attribution in resource.attributions
        }

        expected_attributions = {
            attribution
            for resource in resources[1:]
            for attribution in resource.attributions
        }
        assert expected_attributions == extracted_attributions
        assert set(extracted.scan_results.attribution_to_id.keys()) == (
            expected_attributions | opossum.scan_results.unassigned_attributions
        )

    def test_extraction_keeps_configuration_and_metadata(
        self, opossum_faker: OpossumFaker
    ) -> None:
        resources = self._get_test_resources(opossum_faker)
        scan_results = opossum_faker.scan_results(resources=resources)
        opossum = opossum_faker.opossum(scan_results=scan_results)

        extracted = extract_subtree_impl(opossum, TestExtractSubTreeAttributes.SUBTREE)

        assert extracted.scan_results.config == opossum.scan_results.config
        assert extracted.scan_results.metadata == opossum.scan_results.metadata
        assert (
            extracted.scan_results.base_urls_for_sources
            == opossum.scan_results.base_urls_for_sources
        )
        assert (
            extracted.scan_results.frequent_licenses
            == opossum.scan_results.frequent_licenses
        )
        assert (
            extracted.scan_results.external_attribution_sources
            == opossum.scan_results.external_attribution_sources
        )
        assert (
            extracted.scan_results.unassigned_attributions
            == opossum.scan_results.unassigned_attributions
        )

    def test_extraction_filters_review_results(
        self, opossum_faker: OpossumFaker
    ) -> None:
        resources = self._get_test_resources(opossum_faker)
        scan_results = opossum_faker.scan_results(resources=resources)
        manual_attributions = {
            "1": opossum_faker.manual_attribution(),
            "2": opossum_faker.manual_attribution(),
            "3": opossum_faker.manual_attribution(),
        }
        resources_to_attributions = {
            "/toplevel/resource1.txt": ["1"],
            "/toplevel/folder/": ["2"],
            "/toplevel/folder/resource2.txt": ["3"],
        }
        review_results = opossum_faker.output_file(
            manual_attributions=manual_attributions,
            resources_to_attributions=resources_to_attributions,
        )
        opossum = opossum_faker.opossum(
            review_results=review_results, scan_results=scan_results
        )

        extracted = extract_subtree_impl(opossum, TestExtractSubTreeAttributes.SUBTREE)

        assert extracted.review_results
        assert opossum.review_results  # make mypy happy
        assert extracted.review_results.metadata == opossum.review_results.metadata
        assert {"2", "3"} == set(extracted.review_results.manual_attributions.keys())
        assert {"/toplevel/folder/", "/toplevel/folder/resource2.txt"} == set(
            extracted.review_results.resources_to_attributions.keys()
        )
        assert extracted.review_results.resolved_external_attributions is not None
        assert set(extracted.review_results.resolved_external_attributions).issubset(
            set(extracted.scan_results.attribution_to_id.values())
        )
