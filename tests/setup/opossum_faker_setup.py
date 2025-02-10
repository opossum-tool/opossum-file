# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
from collections.abc import Sequence
from typing import Any, cast

from faker import Faker, Generator

from tests.core.entities.generators.opossum_provider import OpossumProvider
from tests.core.entities.generators.scan_results_provider import ScanResultsProvider


class OpossumFaker(Faker):
    opossum_provider: OpossumProvider
    scan_results_provider: ScanResultsProvider

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
        self.opossum = self.opossum_provider.opossum
        self.scan_results = self.scan_results_provider.scan_results


def setup_opossum_faker(faker: Faker) -> OpossumFaker:
    faker.add_provider(OpossumProvider)
    faker.add_provider(ScanResultsProvider)
    faker = cast(OpossumFaker, faker)
    return faker
