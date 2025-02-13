# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
from typing import cast

from faker import Faker

from tests.input_formats.owasp_deependency_scan.entities.generators.owasp_dependency_report_model_provider import (  # noqa: E501
    OWASPDependencyReportModelProvider,
)


class OwaspFaker(Faker):
    owasp_provider: OWASPDependencyReportModelProvider

    def __init__(self) -> None:
        owasp_provider = OWASPDependencyReportModelProvider(self)
        self.owasp_dependency_report_model = (
            owasp_provider.owasp_dependency_report_model
        )
        self.project_info_model = owasp_provider.project_info_model
        self.data_source_model = owasp_provider.data_source_model
        self.scan_info_model = owasp_provider.scan_info_model
        self.dependencies = owasp_provider.dependencies
        self.dependency_model = owasp_provider.dependency_model
        self.evidence_collected_model = owasp_provider.evidence_collected_model
        self.evidence_model = owasp_provider.evidence_model
        self.package_model = owasp_provider.package_model
        self.package_models = owasp_provider.package_models
        self.vulnerability_model = owasp_provider.vulnerability_model


def setup_owasp_faker(faker: Faker) -> OwaspFaker:
    faker.add_provider(OWASPDependencyReportModelProvider)
    return cast(OwaspFaker, faker)
