# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0


import pytest

from opossum_lib.core.services.merge_opossums import merge_opossums
from tests.setup.opossum_faker_setup import OpossumFaker


class TestMergeOpossumFiles:
    def test_successful_merge(self, opossum_faker: OpossumFaker) -> None:
        opossum1 = opossum_faker.opossum(generate_review_results=True)
        opossum2 = opossum_faker.opossum(generate_review_results=False)
        merged = merge_opossums([opossum1, opossum2])
        assert merged.review_results == opossum1.review_results

    def test_merge_errors_with_multiple_review_results(
        self, opossum_faker: OpossumFaker
    ) -> None:
        opossum1 = opossum_faker.opossum(generate_review_results=True)
        opossum2 = opossum_faker.opossum(generate_review_results=True)
        with pytest.raises(RuntimeError):
            merge_opossums([opossum1, opossum2])
