# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
from pathlib import PurePath
from typing import Any

from faker.providers import BaseProvider
from faker.providers.file import Provider as FileProvider
from faker.providers.misc import Provider as MiscProvider

from opossum_lib.core.entities.opossum_package import OpossumPackage
from opossum_lib.core.entities.resource import Resource, ResourceType
from opossum_lib.core.entities.root_resource import RootResource
from tests.core.entities.generators.package_provider import PackageProvider
from tests.shared.generator_helpers import random_list


class ResourceProvider(BaseProvider):
    misc_provider: MiscProvider
    file_provider: FileProvider
    package_provider: PackageProvider

    def __init__(self, generator: Any):
        super().__init__(generator)
        self.misc_provider = MiscProvider(generator)
        self.file_provider = FileProvider(generator)
        self.package_provider = PackageProvider(generator)

    def resource(
        self,
        path: PurePath | None = None,
        type: ResourceType | None = None,
        attributions: list[OpossumPackage] | None = None,
        children: dict[str, Resource] | None = None,
    ) -> Resource:
        return Resource(
            path=path or PurePath(self.file_provider.file_path(depth=0, extension=[])),
            type=type or self.resource_type(),
            attributions=attributions
            or random_list(
                self,
                entry_generator=lambda: self.package_provider.package(),
                max_number_of_entries=4,
            ),
            children=children or {},
        )

    def resource_tree(
        self, max_depth: int = 4, max_files_per_level: int = 3, max_subfolders: int = 3
    ) -> RootResource:
        tree = self._sub_tree(
            max_depth, max_files_per_level, max_subfolders, current_path=PurePath("")
        )
        return RootResource(children=tree.children)

    def _sub_tree(
        self,
        max_depth: int,
        max_files_per_level: int,
        max_subfolders: int,
        current_path: PurePath,
    ) -> Resource:
        root_node = self.resource(type=ResourceType.FOLDER, path=current_path)
        number_of_files = self.random_int(0, max_files_per_level)
        for _ in range(number_of_files):
            path = self.file_provider.file_name()
            root_node.children[path] = self.resource(
                path=PurePath(root_node.path / path), type=ResourceType.FILE
            )
        if max_depth > 0:
            number_of_subfolders = self.random_int(0, max_subfolders)
            for _ in range(number_of_subfolders):
                path = self.file_provider.file_path(
                    depth=0, extension=[], absolute=False
                )
                root_node.children[path] = self._sub_tree(
                    max_depth=max_depth - 1,
                    max_files_per_level=max_files_per_level,
                    max_subfolders=max_subfolders,
                    current_path=current_path / path,
                )
        return root_node

    def resource_type(self) -> ResourceType:
        return self.random_element(elements=[ResourceType.FOLDER, ResourceType.FILE])
