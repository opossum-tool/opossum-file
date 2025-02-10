# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0


import pytest

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
        # Compare all field except metadata because there the UUID changes
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
        assert expected  # type-checker complains but this can never be None
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
