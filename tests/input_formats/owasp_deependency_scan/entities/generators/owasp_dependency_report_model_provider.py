# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
import hashlib
from typing import Any

from faker.providers import BaseProvider
from faker.providers.date_time.en_US import Provider as DateTimeProvider
from faker.providers.file.en_US import Provider as FileProvider
from faker.providers.lorem.en_US import Provider as LoremProvider
from faker.providers.misc.en_US import Provider as MiscProvider
from faker.providers.person.en_US import Provider as PersonProvider

from opossum_lib.input_formats.owasp_deependency_scan.entities.owasp_dependency_report_model import (  # noqa: E501
    DataSourceModel,
    DependencyModel,
    EvidenceCollectedModel,
    IncludedByModel,
    OWASPDependencyReportModel,
    PackageModel,
    ProjectInfoModel,
    RelatedDependencyModel,
    ScanInfoModel,
    VulnerabilityIdModel,
    VulnerabilityModel,
)
from tests.shared.generator_helpers import entry_or_none, random_dict, random_list


class OWASPDependencyReportModelProvider(BaseProvider):
    person_provider: PersonProvider
    date_provider: DateTimeProvider
    misc_provider: MiscProvider
    lorem_provider: LoremProvider
    file_provider: FileProvider


    def __init__(self, generator: Any):
        super().__init__(generator)
        self.lorem_provider = LoremProvider(generator)
        self.person_provider = PersonProvider(generator)
        self.date_provider = DateTimeProvider(generator)
        self.misc_provider = MiscProvider(generator)
        self.file_provider = FileProvider(generator)

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
            dependencies=dependencies or self.dependencies(),
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

    def dependencies(self, min_number_of_dependencies: int = 0,
                     max_number_of_dependencies: int = 50) -> list[DependencyModel]:

        return random_list(self,
                           max_number_of_entries=max_number_of_dependencies,
                           min_number_of_entries=min_number_of_dependencies,
                           entry_generator=self.dependency_model
                           )

    def dependency_model(self,
         is_virtual: bool | None = None,
         file_name: str | None = None,
         file_path: str | None = None,
         md5: str | None = None,
         sha256: str | None = None,
         sha1: str | None = None,
         description: str | None = None,
         license: str | None = None,
         project_references: list[str] | None = None,
         included_by: list[IncludedByModel] | None = None,
         related_dependencies: list[RelatedDependencyModel] | None = None,
         evidence_collected: EvidenceCollectedModel | None = None,
         packages: list[PackageModel] | None = None,
         vulnerability_ids: list[VulnerabilityIdModel] | None = None,
         suppressed_vulnerability_ids: list[VulnerabilityIdModel] | None = None,
        vulnerabilities: list[VulnerabilityModel] | None = None,
    ) -> DependencyModel:
        word_to_hash = self.lorem_provider.word().encode()
        return DependencyModel(
            is_virtual = is_virtual or self.misc_provider.boolean(),
            file_name = file_name or self.file_provider.file_name(),
            file_path = file_path or self.file_provider.file_path(depth=4),
            sha256 = sha256 or str(hashlib.sha256(word_to_hash)),
            sha1 = sha1 or str(hashlib.sha256(word_to_hash)),
            description= description or self.lorem_provider.paragraph(),
            license= license or self.lorem_provider.paragraph(),
            project_references=project_references or random_list(self,
                                                                 entry_generator=self.lorem_provider.word),
            included_by=included_by or [],
            related_dependencies=related_dependencies or [],
            evidence_collected= evidence_collected or EvidenceCollectedModel(
                vendor_evidence=[],
                product_evidence=[],
                version_evidence=[]
            ),
            packages=packages or [],
            vulnerability_ids=vulnerability_ids or [],
            suppressed_vulnerability_ids=suppressed_vulnerability_ids or [],
            vulnerabilities=vulnerabilities or [],
        )
