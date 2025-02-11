# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
from typing import Any

from faker.providers import BaseProvider
from faker.providers.date_time.en_US import Provider as DateTimeProvider
from faker.providers.lorem.en_US import Provider as LoremProvider
from faker.providers.misc.en_US import Provider as MiscProvider
from faker.providers.person.en_US import Provider as PersonProvider

from opossum_lib.input_formats.owasp_deependency_scan.entities.owasp_dependency_report_model import (  # noqa: E501
    DataSourceModel,
    DependencyModel,
    OWASPDependencyReportModel,
    ProjectInfoModel,
    ScanInfoModel,
)
from tests.shared.generator_helpers import entry_or_none, random_dict, random_list


class OWASPDependencyReportModelProvider(BaseProvider):
    person_provider: PersonProvider
    date_provider: DateTimeProvider
    misc_provider: MiscProvider
    lorem_provider: LoremProvider

    def __init__(self, generator: Any):
        super().__init__(generator)
        self.lorem_provider = LoremProvider(generator)
        self.person_provider = PersonProvider(generator)
        self.date_provider = DateTimeProvider(generator)
        self.misc_provider = MiscProvider(generator)

    def owasp_dependency_report_model(
        self,
        report_schema: str | None = None,
        scan_info: ScanInfoModel | None = None,
        project_info: ProjectInfoModel | None = None,
        dependencies: list[DependencyModel] | None = None,
    ) -> OWASPDependencyReportModel:
        return OWASPDependencyReportModel(
            report_schema=report_schema or self.bothify("#.#"),
            scan_info=scan_info or self.scan_info_model(),
            project_info=project_info or self.project_info_model(),
            dependencies=dependencies or [],
        )

    def scan_info_model(
        self,
        engine_version: str | None = None,
        data_source: list[DataSourceModel] | None = None,
    ) -> ScanInfoModel:
        if not data_source:
            data_source = random_list(
                self,
                self.data_source_model,
                min_number_of_entries=0,
                max_number_of_entries=10,
            )
        return ScanInfoModel(
            engine_version=engine_version or self.bothify("#.#.#"),
            data_source=data_source,
        )

    def data_source_model(self) -> DataSourceModel:
        return DataSourceModel(
            name=self.person_provider.name(),
            timestamp=self.date_provider.date_time().isoformat(),
        )

    def project_info_model(
        self,
        name: str | None = None,
        report_date: str | None = None,
        group_i_d: str | None = None,
        artifact_i_d: str | None = None,
        application_version: str | None = None,
        credits: dict[str, str] | None = None,
    ) -> ProjectInfoModel:
        return ProjectInfoModel(
            name=name or self.person_provider.name(),
            report_date=report_date or self.date_provider.date_time().isoformat(),
            group_i_d=group_i_d
            or entry_or_none(self.misc_provider, self.misc_provider.uuid4()),
            artifact_i_d=artifact_i_d
            or entry_or_none(self.misc_provider, self.misc_provider.uuid4()),
            application_version=application_version
            or entry_or_none(self.misc_provider, self.bothify("#.##.##")),
            credits=credits
            or random_dict(
                self, self.person_provider.name, self.lorem_provider.sentence
            ),
        )
