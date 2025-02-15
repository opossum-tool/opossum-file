# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
import pytest

from opossum_lib.input_formats.opossum.services.convert_to_opossum import (
    convert_to_opossum,
)
from opossum_lib.shared.entities.opossum_input_file_model import (
    OpossumPackageIdentifierModel,
    OpossumPackageModel,
)
from tests.setup.opossum_file_faker_setup import OpossumFileFaker


class TestConvertToOpossum:
    def test_output_file_moved(self, opossum_file_faker: OpossumFileFaker) -> None:
        output_file = opossum_file_faker.output_file()
        input_file = opossum_file_faker.opossum_file_content(out_file=output_file)

        result = convert_to_opossum(input_file)

        assert result.review_results == output_file

    def test_throws_on_duplicate_attributions(
        self, opossum_file_faker: OpossumFileFaker
    ) -> None:
        external_attributions = self._fake_duplicate_external_attributions(
            opossum_file_faker
        )
        file_information = opossum_file_faker.opossum_file_information(
            external_attributions=external_attributions
        )
        input_file = opossum_file_faker.opossum_file_content(in_file=file_information)

        with pytest.raises(RuntimeError, match=r".*attribution was duplicated.*"):
            convert_to_opossum(input_file)

    @staticmethod
    def _fake_duplicate_external_attributions(
        opossum_file_faker: OpossumFileFaker,
    ) -> dict[OpossumPackageIdentifierModel, OpossumPackageModel]:
        external_attributions = opossum_file_faker.external_attributions(
            min_number_of_attributions=2
        )
        package = opossum_file_faker.opossum_package()
        for key in external_attributions:
            external_attributions[key] = package
        return external_attributions
