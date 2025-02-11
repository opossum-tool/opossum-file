#  SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#  #
#  SPDX-License-Identifier: Apache-2.0


from __future__ import annotations

from collections.abc import Generator, Iterable
from enum import Enum, auto
from pathlib import PurePath

from pydantic import BaseModel, ConfigDict

from opossum_lib.core.entities.opossum_package import OpossumPackage
from opossum_lib.shared.entities.opossum_input_file_model import ResourceInFileModel


class ResourceType(Enum):
    FILE = auto()
    FOLDER = auto()


class Resource(BaseModel):
    model_config = ConfigDict(frozen=False, extra="forbid")
    path: PurePath
    type: ResourceType | None = None
    attributions: list[OpossumPackage] = []
    children: dict[str, Resource] = {}

    def to_opossum_file_model(self) -> ResourceInFileModel:
        if self.children or self.type == ResourceType.FOLDER:
            return {
                child.path.relative_to(
                    self.path
                ).as_posix(): child.to_opossum_file_model()
                for child in self.children.values()
            }
        else:
            return 1

    def add_resource(self, resource: Resource) -> None:
        if not resource.path.is_relative_to(self.path):
            raise RuntimeError(
                f"The path {resource.path} is not a child of this node at {self.path}."
            )
        remaining_path_parts = resource.path.relative_to(self.path).parts
        if remaining_path_parts:
            self._add_resource(resource, remaining_path_parts)
        else:
            self._update(resource)

    def _add_resource(
        self, resource: Resource, remaining_path_parts: Iterable[str]
    ) -> None:
        if not remaining_path_parts:
            self._update(resource)
            return
        next, *rest_parts = remaining_path_parts
        if next not in self.children:
            self.children[next] = Resource(path=self.path / next)
        self.children[next]._add_resource(resource, rest_parts)

    def _update(self, other: Resource) -> None:
        if self.path != other.path:
            raise RuntimeError(
                "Trying to merge nodes with different paths: "
                + f"{self.path} vs. {other.path}"
            )
        if self.type and other.type and self.type != other.type:
            raise RuntimeError(
                "Trying to merge incompatible node types. "
                + f"Current node is {self.type}. Other is {other.type}"
            )
        self.type = self.type or other.type
        self.attributions.extend(other.attributions)
        for key, child in other.children.items():
            if key in self.children:
                self.children[key]._update(child)
            else:
                self.children[key] = child


class TopLevelResource(BaseModel):
    model_config = ConfigDict(frozen=False, extra="forbid")
    children: dict[str, Resource] = {}

    def add_resource(self, resource: Resource) -> None:
        remaining_path_parts = resource.path.parts
        if not remaining_path_parts:
            raise RuntimeError(f"Every resource needs a filepath. Got: {resource}")
        next, *rest_parts = remaining_path_parts
        if next not in self.children:
            self.children[next] = Resource(path=PurePath(next))
        self.children[next]._add_resource(resource, rest_parts)

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
