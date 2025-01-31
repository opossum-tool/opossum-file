# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0


from opossum_lib.core.services.merge_opossums import merge_opossums
from tests.setup.opossum_faker_setup import OpossumFaker


class TestMergeOpossumFiles:
    def test_successful_merge(self, opossum_faker: OpossumFaker) -> None:
        opossum1 = opossum_faker.opossum(generate_review_results=False)
        opossum2 = opossum_faker.opossum(generate_review_results=False)
        merged = merge_opossums([opossum1, opossum2])
        assert merged
