# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

import uuid
from typing import Any

from faker.providers import BaseProvider
from faker.providers.date_time import Provider as DatetimeProvider
from faker.providers.lorem.en_US import Provider as LoremProvider
from faker.providers.misc import Provider as MiscProvider

from opossum_lib.shared.entities.opossum_input_file_model import (
    OpossumPackageIdentifierModel,
    OpossumPackageModel,
    ResourceInFileModel,
)
from opossum_lib.shared.entities.opossum_output_file_model import (
    ManualAttributions,
    Metadata,
    OpossumOutputFileModel,
)
from tests.input_formats.opossum.entities.generators.generate_file_information import (
    FileInformationProvider,
)


class OpossumOutputFileProvider(BaseProvider):
    lorem_provider: LoremProvider
    date_time_provider: DatetimeProvider
    misc_provider: MiscProvider
    file_information_provider: FileInformationProvider

    def __init__(self, generator: Any):
        super().__init__(generator)
        self.lorem_provider = LoremProvider(generator)
        self.date_time_provider = DatetimeProvider(generator)
        self.misc_provider = MiscProvider(generator)
        self.file_information_provider = FileInformationProvider(generator)

    def output_file(
        self,
        metadata: Metadata | None = None,
        manual_attributions: dict[str, ManualAttributions] | None = None,
        resources_to_attributions: dict[str, list[str]] | None = None,
        resolved_external_attributions: list[str] | None = None,
    ) -> OpossumOutputFileModel:
        if metadata is None:
            metadata = self.outfile_metadata()
        if manual_attributions is None:
            manual_attributions = self.manual_attributions()
        if resolved_external_attributions is None:
            resolved_external_attributions = self.resolved_external_attributions()
        if resources_to_attributions is None:
            resources_to_attributions = self.resources_to_attributions()
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
    ) -> dict[str, ManualAttributions]:
        return {}

    def resolved_external_attributions(
        self,
        *,
        external_attributions: dict[OpossumPackageIdentifierModel, OpossumPackageModel]
        | None = None,
        min_count: int = 1,
        max_count: int = 5,
    ) -> list[str]:
        length = self.random_int(min=min_count, max=max_count)
        if external_attributions is not None:
            length = min(length, len(external_attributions))
            ids = list(external_attributions.keys())
            return list(self.random_elements(elements=ids, length=length, unique=True))
        else:
            return [str(uuid.uuid4()) for _ in range(length)]

    def resources_to_attributions(
        self,
        *,
        resources: ResourceInFileModel | None = None,
        external_attributions: dict[OpossumPackageIdentifierModel, OpossumPackageModel]
        | None = None,
        min_count: int = 1,
        max_count: int = 5,
        num_attributions: int = 3,
    ) -> dict[str, list[str]]:
        if resources is None:
            resources = self.file_information_provider.resource_in_file()
        if external_attributions is not None:
            attribution_ids = list(external_attributions.keys())
        else:
            attribution_ids = [
                str(uuid.uuid4())
                for _ in range(self.random_int(max=max_count * num_attributions))
            ]

        def resources_to_path(
            resources: ResourceInFileModel,
        ) -> list[str]:
            paths: list[str] = []
            if isinstance(resources, int):
                return paths
            for path_segment, children in resources.items():
                if isinstance(children, int):
                    paths.append(path_segment)
                else:
                    subpaths = resources_to_path(children)
                    paths.extend(path_segment + "/" + subpath for subpath in subpaths)
            return paths

        allpaths = ["/" + path for path in resources_to_path(resources)]
        how_many_paths = min(
            self.random_int(min=min_count, max=max_count), len(allpaths)
        )
        how_many_attributions = min(num_attributions, len(attribution_ids))

        resources_to_attributions = {}
        for path in self.random_elements(
            elements=allpaths, length=how_many_paths, unique=True
        ):
            resources_to_attributions[path] = list(
                self.random_elements(
                    elements=attribution_ids, length=how_many_attributions, unique=True
                )
            )

        return resources_to_attributions
