# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
from collections import defaultdict
from collections.abc import Callable
from typing import Any, Literal, cast

from faker.providers import BaseProvider
from faker.providers.date_time import Provider as DatetimeProvider
from faker.providers.file import Provider as FileProvider
from faker.providers.internet import Provider as InternetProvider
from faker.providers.lorem.en_US import Provider as LoremProvider
from faker.providers.misc import Provider as MiscProvider
from faker.providers.person import Provider as PersonProvider

from opossum_lib.shared.entities.opossum_input_file_model import (
    BaseUrlsForSourcesModel,
    ExternalAttributionSourceModel,
    FrequentLicenseModel,
    MetadataModel,
    OpossumInputFileModel,
    OpossumPackageIdentifierModel,
    OpossumPackageModel,
    ResourceInFileModel,
    ResourcePathModel,
    SourceInfoModel,
)
from tests.shared.generator_helpers import entry_or_none, random_list


class MetadataProvider(BaseProvider):
    lorem_provider: LoremProvider
    date_time_provider: DatetimeProvider
    misc_provider: MiscProvider

    def __init__(self, generator: Any):
        super().__init__(generator)
        self.lorem_provider = LoremProvider(generator)
        self.date_time_provider = DatetimeProvider(generator)
        self.misc_provider = MiscProvider(generator)

    def opossum_input_metadata(
        self,
        *,
        project_id: str | None = None,
        file_creation_date: str | None = None,
        project_title: str | None = None,
        project_version: str | None = None,
        expected_release_date: str | None = None,
        build_date: str | None = None,
    ) -> MetadataModel:
        return MetadataModel(
            project_id=project_id or "project-id-" + self.lorem_provider.word(),
            file_creation_date=file_creation_date
            or self.date_time_provider.date_time().isoformat(),
            project_title=project_title or "project-id-" + self.lorem_provider.word(),
            project_version=project_version
            or entry_or_none(self.misc_provider, self.numerify("##.##.##")),
            expected_release_date=expected_release_date
            or entry_or_none(
                self.misc_provider, self.date_time_provider.date_time().isoformat()
            ),
            build_date=build_date
            or entry_or_none(
                self.misc_provider, self.date_time_provider.date_time().isoformat()
            ),
        )


class FileInformationProvider(BaseProvider):
    metadata_provider: MetadataProvider
    file_provider: FileProvider
    lorem_provider: LoremProvider
    misc_provider: MiscProvider
    person_provider: PersonProvider
    internet_provider: InternetProvider

    def __init__(self, generator: Any):
        super().__init__(generator)
        self.metadata_provider = MetadataProvider(generator)
        self.file_provider = FileProvider(generator)
        self.lorem_provider = LoremProvider(generator)
        self.misc_provider = MiscProvider(generator)
        self.person_provider = PersonProvider(generator)
        self.internet_provider = InternetProvider(generator)

    def opossum_file_information(
        self,
        *,
        metadata: MetadataModel | None = None,
        resources: ResourceInFileModel | None = None,
        external_attributions: dict[OpossumPackageIdentifierModel, OpossumPackageModel]
        | None = None,
        resources_to_attributions: dict[
            ResourcePathModel, list[OpossumPackageIdentifierModel]
        ]
        | None = None,
        attribution_breakpoints: list[str] | None = None,
        external_attribution_sources: dict[str, ExternalAttributionSourceModel]
        | None = None,
        frequent_licenses: list[FrequentLicenseModel] | None = None,
        files_with_children: list[str] | None = None,
        base_urls_for_sources: BaseUrlsForSourcesModel | None = None,
    ) -> OpossumInputFileModel:
        generated_resources = resources or self.resource_in_file()
        attributions = external_attributions or self.external_attributions(
            min_number_of_attributions=25
        )
        return OpossumInputFileModel(
            metadata=metadata or self.metadata_provider.opossum_input_metadata(),
            resources=generated_resources,
            external_attributions=attributions,
            resources_to_attributions=resources_to_attributions
            or self.resources_to_attributions(
                resources=generated_resources, external_attributions=attributions
            ),
            attribution_breakpoints=attribution_breakpoints
            or self.attribution_breakpoints(),
            external_attribution_sources=external_attribution_sources
            or self.external_attribution_sources(),
            frequent_licenses=frequent_licenses,
            files_with_children=files_with_children,
            base_urls_for_sources=base_urls_for_sources,
        )

    def resource_in_file(
        self,
        depth: int = 3,
        max_folders_per_level: int = 3,
        max_files_per_level: int = 3,
    ) -> ResourceInFileModel:
        if depth == 0:
            files = self.random_int(0, max_files_per_level)
            return {
                self.file_provider.file_name(category="text"): 1 for _ in range(files)
            }
        else:
            files = self.random_int(0, max_files_per_level)
            file_result = {
                self.file_provider.file_name(category="text"): 1 for _ in range(files)
            }
            folders = self.random_int(1, max_folders_per_level)
            folder_result = {
                self.lorem_provider.word(): self.resource_in_file(
                    depth=depth - 1,
                    max_files_per_level=max_files_per_level,
                    max_folders_per_level=max_folders_per_level,
                )
                for _ in range(folders)
            }
            return {**file_result, **folder_result}

    def source_info(
        self,
        name: str | None = None,
        document_confidence: int | float | None = None,
        additional_name: str | None = None,
    ) -> SourceInfoModel:
        return SourceInfoModel(
            name=name or self.person_provider.name(),
            document_confidence=document_confidence
            or entry_or_none(self.misc_provider, self.random_int(0, 100)),
            additional_name=additional_name
            or entry_or_none(self.misc_provider, self.person_provider.name()),
        )

    def opossum_package(
        self,
        source: SourceInfoModel | None = None,
        attribution_confidence: int | None = None,
        comment: str | None = None,
        package_name: str | None = None,
        package_version: str | None = None,
        package_namespace: str | None = None,
        package_type: str | None = None,
        package_p_u_r_l_appendix: str | None = None,
        copyright: str | None = None,
        license_name: str | None = None,
        license_text: str | None = None,
        url: str | None = None,
        first_party: bool | None = None,
        exclude_from_notice: bool | None = None,
        pre_selected: bool | None = None,
        follow_up: Literal["FOLLOW_UP"] | None = None,
        origin_id: str | None = None,
        origin_ids: list[str] | None = None,
        criticality: Literal["high"] | Literal["medium"] | None = None,
        was_preferred: bool | None = None,
    ) -> OpossumPackageModel:
        return OpossumPackageModel(
            source=source or self.source_info(),
            attribution_confidence=attribution_confidence
            or entry_or_none(self.misc_provider, self.random_int()),
            comment=comment
            or entry_or_none(
                self.misc_provider, self.lorem_provider.paragraph(nb_sentences=5)
            ),
            package_name=package_name
            or entry_or_none(self.misc_provider, self.person_provider.name()),
            package_version=package_version
            or entry_or_none(self.misc_provider, self.numerify("##.##.##")),
            package_namespace=package_namespace
            or entry_or_none(self.misc_provider, self.internet_provider.domain_name()),
            package_type=package_type
            or entry_or_none(
                self.misc_provider,
                self.lorem_provider.word(ext_word_list=["maven", "github"]),
            ),
            package_p_u_r_l_appendix=package_p_u_r_l_appendix
            or entry_or_none(
                self.misc_provider, self.lorem_provider.paragraph(nb_sentences=1)
            ),
            copyright=copyright
            or entry_or_none(
                self.misc_provider, self.lorem_provider.paragraph(nb_sentences=1)
            ),
            license_name=license_name
            or entry_or_none(self.misc_provider, self.person_provider.name()),
            license_text=license_text
            or entry_or_none(
                self.misc_provider, self.lorem_provider.paragraph(nb_sentences=10)
            ),
            url=url
            or entry_or_none(self.misc_provider, self.internet_provider.uri(deep=5)),
            first_party=first_party
            or entry_or_none(self.misc_provider, self.misc_provider.boolean()),
            exclude_from_notice=exclude_from_notice
            or entry_or_none(self.misc_provider, self.misc_provider.boolean()),
            pre_selected=pre_selected
            or entry_or_none(self.misc_provider, self.misc_provider.boolean()),
            follow_up=follow_up or entry_or_none(self.misc_provider, "FOLLOW_UP"),
            origin_id=origin_id
            or entry_or_none(self.misc_provider, self.misc_provider.uuid4()),
            origin_ids=origin_ids
            or random_list(self, cast(Callable[[], str], self.misc_provider.uuid4)),
            criticality=criticality
            or entry_or_none(
                self.misc_provider,
                self.misc_provider.random_element(["high", "medium"]),
            ),
            was_preferred=was_preferred
            or entry_or_none(self.misc_provider, self.misc_provider.boolean()),
        )

    def external_attributions(
        self, max_number_of_attributions: int = 50, min_number_of_attributions: int = 5
    ) -> dict[OpossumPackageIdentifierModel, OpossumPackageModel]:
        number_of_attributions = self.random_int(
            min_number_of_attributions, max_number_of_attributions
        )
        return {
            cast(str, self.misc_provider.uuid4()): self.opossum_package()
            for _ in range(number_of_attributions)
        }

    def resources_to_attributions(
        self,
        resources: ResourceInFileModel,
        external_attributions: dict[OpossumPackageIdentifierModel, OpossumPackageModel],
    ) -> dict[ResourcePathModel, list[OpossumPackageIdentifierModel]]:
        def get_file_paths(
            resource: ResourceInFileModel, current_path: str
        ) -> list[str]:
            if isinstance(resource, int):
                return []
            resulting_file_paths = []
            for key, value in resource.items():
                if isinstance(value, dict):
                    resulting_file_paths += get_file_paths(
                        value, current_path + key + "/"
                    )
                else:
                    resulting_file_paths.append(current_path + key)
            return resulting_file_paths

        file_paths = get_file_paths(resources, "/")
        package_identifiers = list(external_attributions.keys())
        result = defaultdict(list)
        for path in file_paths:
            if len(package_identifiers) > 0:
                result[path].append(package_identifiers.pop())
            else:
                break
        if len(file_paths) > 0:
            for package_identifier in package_identifiers:
                path = self.random_element(file_paths)
                result[path].append(package_identifier)
        return result

    def attribution_breakpoints(self, max_nb_of_breakpoints: int = 5) -> list[str]:
        nb_of_breakpoints = self.random_int(1, max_nb_of_breakpoints)
        return [
            self.file_provider.file_path(extension=[], depth=3)
            for _ in range(nb_of_breakpoints)
        ]

    def external_attribution_source(
        self,
        name: str | None = None,
        priority: int | None = None,
        is_relevant_for_preferred: bool | None = None,
    ) -> ExternalAttributionSourceModel:
        return ExternalAttributionSourceModel(
            name=name or self.person_provider.name(),
            priority=priority or self.random_int(1, 100),
            is_relevant_for_preferred=is_relevant_for_preferred
            or entry_or_none(self.misc_provider, self.misc_provider.boolean()),
        )

    def external_attribution_sources(
        self, max_nb_of_external_attributions: int = 5
    ) -> dict[str, ExternalAttributionSourceModel]:
        nb_of_external_attributions = self.random_int(
            1, max_nb_of_external_attributions
        )
        return {
            self.person_provider.first_name(): self.external_attribution_source()
            for _ in range(nb_of_external_attributions)
        }
