# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
from copy import deepcopy

from opossum_lib.input_formats.opossum.services.convert_to_opossum import (
    convert_to_opossum,
)
from opossum_lib.shared.entities.opossum_file_model import OpossumFileModel
from tests.setup.opossum_file_faker_setup import OpossumFileFaker
from tests.shared.comparison_helpers import _assert_equal_or_both_falsy


class TestConversionRoundtrip:
    def test_roundtrip(self, opossum_file_faker: OpossumFileFaker) -> None:
        start_file_content = opossum_file_faker.opossum_file_content()
        TestConversionRoundtrip._check_round_trip(start_file_content)

    def test_input_file_only(self, opossum_file_faker: OpossumFileFaker) -> None:
        start_file_content = OpossumFileModel(
            input_file=opossum_file_faker.opossum_file_information()
        )
        TestConversionRoundtrip._check_round_trip(start_file_content)

    def test_surplus_attributions(self, opossum_file_faker: OpossumFileFaker) -> None:
        start_file_content = opossum_file_faker.opossum_file_content()
        start_file_content.input_file.external_attributions.update(
            opossum_file_faker.external_attributions()
        )
        TestConversionRoundtrip._check_round_trip(start_file_content)

    @staticmethod
    def _check_round_trip(start_file_content: OpossumFileModel) -> None:
        expected_file_content = deepcopy(start_file_content)
        result = convert_to_opossum(start_file_content).to_opossum_file_model()

        assert expected_file_content.output_file == result.output_file

        expected_input_file = expected_file_content.input_file
        result_input_file = result.input_file
        _assert_equal_or_both_falsy(
            expected_input_file.metadata, result_input_file.metadata
        )
        _assert_equal_or_both_falsy(
            expected_input_file.resources, result_input_file.resources
        )
        _assert_equal_or_both_falsy(
            expected_input_file.external_attributions,
            result_input_file.external_attributions,
        )
        _assert_equal_or_both_falsy(
            expected_input_file.resources_to_attributions,
            result_input_file.resources_to_attributions,
        )
        _assert_equal_or_both_falsy(
            expected_input_file.attribution_breakpoints,
            result_input_file.attribution_breakpoints,
        )
        _assert_equal_or_both_falsy(
            expected_input_file.external_attribution_sources,
            result_input_file.external_attribution_sources,
        )
        _assert_equal_or_both_falsy(
            expected_input_file.frequent_licenses, result_input_file.frequent_licenses
        )
        _assert_equal_or_both_falsy(
            expected_input_file.files_with_children,
            result_input_file.files_with_children,
        )
        expectect_base_urls_data = (
            expected_input_file.base_urls_for_sources.model_dump()
            if expected_input_file.base_urls_for_sources
            else {}
        )
        result_base_urls_data = (
            result_input_file.base_urls_for_sources.model_dump()
            if result_input_file.base_urls_for_sources
            else {}
        )
        _assert_equal_or_both_falsy(
            expectect_base_urls_data,
            result_base_urls_data,
        )
