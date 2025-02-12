#  SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#  #
#  SPDX-License-Identifier: Apache-2.0

from collections.abc import Generator
from pathlib import PurePath

from pydantic import BaseModel, ConfigDict

from opossum_lib.core.entities.resource import Resource
from opossum_lib.shared.entities.opossum_input_file_model import ResourceInFileModel


class RootResource(BaseModel):
    model_config = ConfigDict(frozen=False, extra="forbid")
    children: dict[str, Resource] = {}

    def add_resource(self, resource: Resource) -> None:
        remaining_path_parts = resource.path.parts
        if not remaining_path_parts:
            raise RuntimeError(f"Every resource needs a filepath. Got: {resource}")
        first_path_segment = remaining_path_parts[0]
        if first_path_segment not in self.children:
            self.children[first_path_segment] = Resource(
                path=PurePath(first_path_segment)
            )
        self.children[first_path_segment].add_resource(resource)

    def to_opossum_file_model(self) -> ResourceInFileModel:
        return {
            child.path.as_posix(): child.to_opossum_file_model()
            for child in self.children.values()
        }

    def all_resources(self) -> Generator[Resource]:
        def iterate(node: Resource) -> Generator[Resource]:
            yield node
            for child in node.children.values():
                yield from iterate(child)

        for child in self.children.values():
            yield from iterate(child)
