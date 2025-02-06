# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
from collections.abc import Sequence
from typing import Any, cast

from faker import Faker, Generator

from tests.core.entities.generators.opossum_provider import OpossumProvider
from tests.core.entities.generators.scan_results_provider import ScanResultsProvider
from tests.input_formats.opossum.entities.generators.generate_outfile_information import (  # noqa: E501
    OpossumOutputFileProvider,
)


class OpossumFaker(Faker):
    opossum_provider: OpossumProvider
    scan_results_provider: ScanResultsProvider
    review_result_provider: OpossumOutputFileProvider

    def __init__(
        self,
        locale: str | Sequence[str] | dict[str, int | float] | None = None,
        providers: list[str] | None = None,
        generator: Generator | None = None,
        includes: list[str] | None = None,
        use_weighting: bool = True,
        **config: Any,
    ):
        super().__init__(
            locale, providers, generator, includes, use_weighting, **config
        )
        self.opossum_provider = OpossumProvider(self)
        self.scan_results_provider = ScanResultsProvider(self)
        self.review_result_provider = OpossumOutputFileProvider(self)
        self.opossum = self.opossum_provider.opossum
        self.scan_results = self.scan_results_provider.scan_results
        self.output_file = self.review_result_provider.output_file
        self.outfile_metadata = self.review_result_provider.outfile_metadata
        self.manual_attributions = self.review_result_provider.manual_attributions
        self.resources_to_attributions = (
            self.review_result_provider.resources_to_attributions
        )
        self.resolved_external_attributions = (
            self.review_result_provider.resolved_external_attributions
        )


def setup_opossum_faker(faker: Faker) -> OpossumFaker:
    faker.add_provider(OpossumProvider)
    faker.add_provider(ScanResultsProvider)
    faker.add_provider(OpossumOutputFileProvider)
    faker = cast(OpossumFaker, faker)
    return faker
