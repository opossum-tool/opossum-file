# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
from collections.abc import Sequence
from typing import Any, cast

from faker import Faker, Generator

from tests.input_formats.owasp_deependency_scan.entities.generators.owasp_dependency_report_model_provider import (  # noqa: E501
    OWASPDependencyReportModelProvider,
)


class OwaspFaker(Faker):
    owasp_provider: OWASPDependencyReportModelProvider

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
        self.owasp_dependency_report_model = (
            self.owasp_provider.owasp_dependency_report_model
        )
        self.project_info_model = self.owasp_provider.project_info_model
        self.data_source_model = self.owasp_provider.data_source_model
        self.scan_info_model = self.owasp_provider.scan_info_model


def setup_owasp_faker(faker: Faker) -> OwaspFaker:
    faker.add_provider(OWASPDependencyReportModelProvider)
    faker = cast(OwaspFaker, faker)
    return faker
