# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

from collections.abc import Callable
from typing import Any, cast

from faker.providers import BaseProvider
from faker.providers.date_time import Provider as DatetimeProvider
from faker.providers.internet import Provider as InternetProvider
from faker.providers.lorem.en_US import Provider as LoremProvider
from faker.providers.misc import Provider as MiscProvider
from faker.providers.person import Provider as PersonProvider

from opossum_lib.core.entities.scan_results import ScanResults
from opossum_lib.shared.entities.opossum_input_file_model import (
    OpossumPackageIdentifierModel,
    ResourceInFileModel,
)
from opossum_lib.shared.entities.opossum_output_file_model import (
    FollowUp,
    ManualAttributions,
    Metadata,
    OpossumOutputFileModel,
)
from tests.input_formats.opossum.entities.generators.generate_file_information import (
    FileInformationProvider,
)
from tests.shared.generator_helpers import entry_or_none, random_list


class OpossumOutputFileProvider(BaseProvider):
    lorem_provider: LoremProvider
    date_time_provider: DatetimeProvider
    misc_provider: MiscProvider
    file_information_provider: FileInformationProvider
    internet_provider: InternetProvider
    person_provider: PersonProvider

    def __init__(self, generator: Any):
        super().__init__(generator)
        self.lorem_provider = LoremProvider(generator)
        self.date_time_provider = DatetimeProvider(generator)
        self.misc_provider = MiscProvider(generator)
        self.file_information_provider = FileInformationProvider(generator)
        self.internet_provider = InternetProvider(generator)
        self.person_provider = PersonProvider(generator)

    def output_file(
        self,
        metadata: Metadata | None = None,
        manual_attributions: dict[str, ManualAttributions] | None = None,
        resources_to_attributions: dict[str, list[str]] | None = None,
        resolved_external_attributions: list[str] | None = None,
        scan_results: ScanResults | None = None,
    ) -> OpossumOutputFileModel:
        if metadata is None:
            project_id = scan_results.metadata.project_id if scan_results else None
            file_creation_date = (
                scan_results.metadata.file_creation_date if scan_results else None
            )
            metadata = self.outfile_metadata(
                project_id=project_id,
                file_creation_date=file_creation_date,
            )
        if manual_attributions is None:
            manual_attributions = self.manual_attributions()
        if resolved_external_attributions is None:
            external_attributions_ids = (
                list(scan_results.attribution_to_id.values()) if scan_results else None
            )
            resolved_external_attributions = self.resolved_external_attributions(
                external_attributions_ids=external_attributions_ids
            )
        if resources_to_attributions is None:
            all_paths = None
            if scan_results:
                all_paths = [
                    str(resource.path)
                    for resource in scan_results.resources.all_resources()
                ]
            resources_to_attributions = self.resources_to_attributions(
                manual_attributions=manual_attributions,
                all_paths=all_paths,
            )
        return OpossumOutputFileModel(
            metadata=metadata,
            manual_attributions=manual_attributions,
            resources_to_attributions=resources_to_attributions,
            resolved_external_attributions=resolved_external_attributions,
        )

    def outfile_metadata(
        self,
        *,
        project_id: str | None = None,
        file_creation_date: str | None = None,
    ) -> Metadata:
        return Metadata(
            project_id=project_id or "project-id-" + self.lorem_provider.word(),
            file_creation_date=file_creation_date
            or self.date_time_provider.date_time().isoformat(),
            input_file_md5_checksum=None,
        )

    def manual_attributions(
        self,
        min_count: int = 1,
        max_count: int = 5,
    ) -> dict[str, ManualAttributions]:
        number_to_generate = self.random_int(min=min_count, max=max_count)
        return {
            str(self.misc_provider.uuid4()): self.manual_attribution()
            for _ in range(number_to_generate)
        }

    def manual_attribution(
        self,
        package_name: str | None = None,
        package_version: str | None = None,
        package_namespace: str | None = None,
        package_type: str | None = None,
        package_p_u_r_l_appendix: str | None = None,
        url: str | None = None,
        license_name: str | None = None,
        license_text: str | None = None,
        attribution_confidence: float | None = None,
        comment: str | None = None,
        criticality: str | None = None,
        copyright: str | None = None,
        first_party: bool | None = None,
        pre_selected: bool | None = None,
        exclude_from_notice: bool | None = None,
        follow_up: FollowUp | None = None,
        origin_id: str | None = None,
        origin_ids: list[str] | None = None,
        needs_review: bool | None = None,
        preferred: bool | None = None,
        preferred_over_origin_ids: list[str] | None = None,
        was_preferred: bool | None = None,
    ) -> ManualAttributions:
        return ManualAttributions(
            attribution_confidence=attribution_confidence
            or entry_or_none(self.misc_provider, self.random_int(max=100)),
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
            needs_review=needs_review
            or entry_or_none(self.misc_provider, self.misc_provider.boolean()),
            preferred=preferred
            or entry_or_none(self.misc_provider, self.misc_provider.boolean()),
            preferred_over_origin_ids=preferred_over_origin_ids
            or entry_or_none(
                self.misc_provider,
                random_list(self, cast(Callable[[], str], self.misc_provider.uuid4)),
            ),
        )

    def resolved_external_attributions(
        self,
        *,
        external_attributions_ids: list[OpossumPackageIdentifierModel] | None = None,
        min_count: int = 1,
        max_count: int = 5,
    ) -> list[str]:
        length = self.random_int(min=min_count, max=max_count)
        if external_attributions_ids is not None:
            length = min(length, len(external_attributions_ids))
            return list(
                self.random_elements(
                    external_attributions_ids, length=length, unique=True
                )
            )
        else:
            return [str(self.misc_provider.uuid4()) for _ in range(length)]

    def _resources_to_path(
        self,
        resources: ResourceInFileModel,
    ) -> list[str]:
        paths: list[str] = []
        if isinstance(resources, int):
            return paths
        for path_segment, children in resources.items():
            if isinstance(children, int):
                paths.append(path_segment)
            else:
                subpaths = self._resources_to_path(children)
                paths.extend(path_segment + "/" + subpath for subpath in subpaths)
        return paths

    def _ensure_root_prefix(self, path: str) -> str:
        if not path.startswith("/"):
            return "/" + path
        else:
            return path

    def resources_to_attributions(
        self,
        *,
        resources: ResourceInFileModel | None = None,
        manual_attributions: dict[str, ManualAttributions] | None = None,
        all_paths: list[str] | None,
        min_count: int = 1,
        max_count: int = 5,
        num_attributions: int = 3,
    ) -> dict[str, list[str]]:
        if manual_attributions is None:
            manual_attributions = self.manual_attributions()
        if manual_attributions is not None:
            attribution_ids = list(manual_attributions.keys())
        else:
            attribution_ids = [
                self.misc_provider.uuid4()
                for _ in range(self.random_int(max=max_count * num_attributions))
            ]

        all_paths = all_paths or []
        if resources:
            all_paths.extend(self._resources_to_path(resources))
        if not all_paths:
            resources = self.file_information_provider.resource_in_file()
            all_paths.extend(self._resources_to_path(resources))
        all_paths = [self._ensure_root_prefix(path) for path in all_paths]

        number_of_paths = min(
            self.random_int(min=min_count, max=max_count), len(all_paths)
        )
        number_of_attributions = min(num_attributions, len(attribution_ids))

        resources_to_attributions = {}
        for path in self.random_elements(
            elements=all_paths, length=number_of_paths, unique=True
        ):
            resources_to_attributions[path] = list(
                self.random_elements(
                    elements=attribution_ids, length=number_of_attributions, unique=True
                )
            )

        return resources_to_attributions
