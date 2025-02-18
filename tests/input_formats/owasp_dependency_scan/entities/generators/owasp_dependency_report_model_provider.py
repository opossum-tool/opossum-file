# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
import hashlib
from typing import Any

from faker.providers import BaseProvider
from faker.providers.date_time.en_US import Provider as DateTimeProvider
from faker.providers.file.en_US import Provider as FileProvider
from faker.providers.internet.en_US import Provider as InternetProvider
from faker.providers.lorem.en_US import Provider as LoremProvider
from faker.providers.misc.en_US import Provider as MiscProvider
from faker.providers.person.en_US import Provider as PersonProvider
from packageurl import PackageURL

from opossum_lib.input_formats.owasp_dependency_scan.entities.owasp_dependency_report_model import (  # noqa: E501
    CvssV2Model,
    CvssV3Model,
    CvssV4Model,
    DataSourceModel,
    DependencyModel,
    EvidenceCollectedModel,
    EvidenceModel,
    IncludedByModel,
    OWASPDependencyReportModel,
    PackageModel,
    ProjectInfoModel,
    RelatedDependencyModel,
    ScanInfoModel,
    VulnerabilityIdModel,
    VulnerabilityModel,
)
from tests.shared.generator_helpers import (
    entry_or_none,
    random_bool,
    random_dict,
    random_list,
)


class OWASPDependencyReportModelProvider(BaseProvider):
    person_provider: PersonProvider
    date_provider: DateTimeProvider
    misc_provider: MiscProvider
    lorem_provider: LoremProvider
    file_provider: FileProvider
    internet_provider: InternetProvider

    def __init__(self, generator: Any):
        super().__init__(generator)
        self.lorem_provider = LoremProvider(generator)
        self.person_provider = PersonProvider(generator)
        self.date_provider = DateTimeProvider(generator)
        self.misc_provider = MiscProvider(generator)
        self.file_provider = FileProvider(generator)
        self.internet_provider = InternetProvider(generator)

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

    def dependencies(
        self, min_number_of_dependencies: int = 0, max_number_of_dependencies: int = 50
    ) -> list[DependencyModel]:
        return random_list(
            self,
            max_number_of_entries=max_number_of_dependencies,
            min_number_of_entries=min_number_of_dependencies,
            entry_generator=self.dependency_model,
        )

    def dependency_model(
        self,
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
        generated_packages = self._generate_packages(packages)
        return DependencyModel(
            is_virtual=random_bool(self.misc_provider, default=is_virtual),
            file_name=file_name or self.file_provider.file_name(),
            file_path=file_path or self.file_provider.file_path(depth=4),
            md5=md5 or self.misc_provider.md5(),
            packages=generated_packages,
            sha256=sha256 or str(hashlib.sha256(word_to_hash)),
            sha1=sha1 or str(hashlib.sha256(word_to_hash)),
            description=description or self.lorem_provider.paragraph(),
            license=license or self.lorem_provider.paragraph(),
            project_references=project_references
            or random_list(self, entry_generator=self.lorem_provider.word),
            included_by=included_by or [],
            related_dependencies=related_dependencies or [],
            evidence_collected=evidence_collected or self.evidence_collected_model(),
            vulnerability_ids=vulnerability_ids,
            suppressed_vulnerability_ids=suppressed_vulnerability_ids or [],
            vulnerabilities=self._generate_vulnerabilities(vulnerabilities),
        )

    def _generate_vulnerabilities(
        self, default: list[VulnerabilityModel] | None
    ) -> list[VulnerabilityModel] | None:
        if default is None:
            return entry_or_none(
                self.misc_provider, random_list(self, self.vulnerability_model)
            )
        else:
            return default

    def _generate_packages(
        self, default: list[PackageModel] | None
    ) -> list[PackageModel] | None:
        if default is not None:
            return default
        else:
            return entry_or_none(self.misc_provider, self.package_models())

    def evidence_collected_model(
        self,
        product_evidence: list[EvidenceModel] | None = None,
        version_evidence: list[EvidenceModel] | None = None,
        vendor_evidence: list[EvidenceModel] | None = None,
    ) -> EvidenceCollectedModel:
        return EvidenceCollectedModel(
            product_evidence=self._generate_evidences(product_evidence, "product"),
            version_evidence=self._generate_evidences(version_evidence, "version"),
            vendor_evidence=self._generate_evidences(vendor_evidence, "vendor"),
        )

    def _generate_evidences(
        self, override: list[EvidenceModel] | None, type: str
    ) -> list[EvidenceModel]:
        return override or random_list(
            self,
            entry_generator=lambda: self.evidence_model(type=type),
            min_number_of_entries=0,
        )

    def evidence_model(
        self,
        type: str | None = None,
        confidence: str | None = None,
        source: str | None = None,
        name: str | None = None,
        value: str | None = None,
    ) -> EvidenceModel:
        return EvidenceModel(
            type=type
            or self.misc_provider.random_element(
                elements=["vendor", "product", "version"]
            ),
            confidence=confidence
            or self.misc_provider.random_element(
                elements=["HIGH", "MEDIUM", "LOW", "HIGHEST"]
            ),
            source=source
            or self.misc_provider.random_element(elements=["file", "magic"]),
            name=name
            or self.misc_provider.random_element(
                elements=[
                    "author",
                    "bugs",
                    "description",
                    "homepage",
                    "name",
                    "version",
                ]
            ),
            value=value or self.file_provider.file_name(extension=""),
        )

    def package_models(
        self, min_nb_of_packages: int = 0, max_nb_of_packages: int = 3
    ) -> list[PackageModel]:
        number_of_packages = self.random_int(min_nb_of_packages, max_nb_of_packages)
        return [self.package_model() for _ in range(number_of_packages)]

    def package_model(
        self,
        id: str | None = None,
        confidence: str | None = None,
        url: str | None = None,
        description: str | None = None,
        notes: str | None = None,
    ) -> PackageModel:
        return PackageModel(
            id=id
            or PackageURL(
                type=self.lorem_provider.word(),
                subpath=self.internet_provider.uri_path(),
                version=self.bothify("##.##.##"),
                namespace=self.internet_provider.domain_name(),
                name=self.internet_provider.domain_name(),
            ).to_string(),
            confidence=confidence
            or entry_or_none(
                self.misc_provider,
                self.misc_provider.random_element(
                    elements=["HIGH", "MEDIUM", "LOW", "HIGHEST"]
                ),
            ),
            url=url or entry_or_none(self.misc_provider, self.internet_provider.url()),
            description=description
            or entry_or_none(self.misc_provider, self.lorem_provider.paragraph()),
            notes=notes
            or entry_or_none(self.misc_provider, self.lorem_provider.paragraph()),
        )

    def vulnerability_model(
        self,
        source: str | None = None,
        name: str | None = None,
        cvssv2: CvssV2Model | None = None,
        cvssv3: CvssV3Model | None = None,
        cvssv4: CvssV4Model | None = None,
        cwes: list[str] | None = None,
        description: str | None = None,
        notes: str | None = None,
        references: list[dict] | None = None,
        vulnerable_software: list[dict] | None = None,
    ) -> VulnerabilityModel:
        return VulnerabilityModel(
            source=source or self.file_provider.file_name(extension=""),
            name=name or self.file_provider.file_name(extension=""),
            cvssv2=cvssv2,
            cvssv3=cvssv3,
            cvssv4=cvssv4,
            cwes=cwes,
            description=description or self.lorem_provider.paragraph(),
            notes=notes or self.lorem_provider.paragraph(),
            references=references,
            vulnerable_software=vulnerable_software,
        )
