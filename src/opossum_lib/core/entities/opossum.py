# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import uuid
from collections import defaultdict
from collections.abc import Iterable
from copy import deepcopy
from dataclasses import field
from enum import Enum, auto
from pathlib import PurePath
from typing import Literal

from pydantic import BaseModel, ConfigDict

import opossum_lib.shared.entities.opossum_input_file_model as opossum_file
from opossum_lib.shared.entities.opossum_file_model import OpossumFileModel
from opossum_lib.shared.entities.opossum_output_file_model import OpossumOutputFileModel

type OpossumPackageIdentifier = str
type ResourcePath = str


def _convert_path_to_str(path: PurePath) -> str:
    return str(path).replace("\\", "/")


def default_attribution_id_mapper() -> dict[OpossumPackage, str]:
    return defaultdict(lambda: str(uuid.uuid4()))


class Opossum(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    scan_results: ScanResults
    review_results: OpossumOutputFileModel | None = None

    def to_opossum_file_format(self) -> OpossumFileModel:
        return OpossumFileModel(
            input_file=self.scan_results.to_opossum_file_format(),
            output_file=self.review_results,
        )


class ScanResults(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    metadata: Metadata
    resources: list[Resource]
    attribution_breakpoints: list[str] = []
    external_attribution_sources: dict[str, ExternalAttributionSource] = {}
    frequent_licenses: list[FrequentLicense] | None = None
    files_with_children: list[str] | None = None
    base_urls_for_sources: BaseUrlsForSources | None = None
    attribution_to_id: dict[OpossumPackage, str] = field(
        default_factory=default_attribution_id_mapper
    )
    unassigned_attributions: list[OpossumPackage] = []

    def to_opossum_file_format(self) -> opossum_file.OpossumInputFileModel:
        external_attributions, resources_to_attributions = (
            self.create_attribution_mapping(self.resources)
        )
        external_attributions.update(self._get_unassigned_attributions())

        frequent_licenses = None
        if self.frequent_licenses:
            frequent_licenses = [
                license.to_opossum_file_format() for license in self.frequent_licenses
            ]
        base_urls_for_sources = (
            self.base_urls_for_sources
            and self.base_urls_for_sources.to_opossum_file_format()
        )

        external_attribution_sources = {
            key: val.to_opossum_file_format()
            for (key, val) in self.external_attribution_sources.items()
        }

        return opossum_file.OpossumInputFileModel(
            metadata=self.metadata.to_opossum_file_format(),
            resources={
                str(resource.path): resource.to_opossum_file_format()
                for resource in self.resources
            },
            external_attributions=external_attributions,
            resources_to_attributions=resources_to_attributions,
            attribution_breakpoints=deepcopy(self.attribution_breakpoints),
            external_attribution_sources=external_attribution_sources,
            frequent_licenses=frequent_licenses,
            files_with_children=deepcopy(self.files_with_children),
            base_urls_for_sources=base_urls_for_sources,
        )

    def _get_unassigned_attributions(
        self,
    ) -> dict[opossum_file.OpossumPackageIdentifier, opossum_file.OpossumPackageModel]:
        if self.unassigned_attributions:
            result = {}
            for unassigned_attribution in self.unassigned_attributions:
                if unassigned_attribution in self.attribution_to_id:
                    package_identifier = self.attribution_to_id[unassigned_attribution]
                    result[package_identifier] = (
                        unassigned_attribution.to_opossum_file_format()
                    )
                else:
                    package_identifier = str(uuid.uuid4())
                    self.attribution_to_id[unassigned_attribution] = package_identifier
                    result[package_identifier] = (
                        unassigned_attribution.to_opossum_file_format()
                    )
            return result
        else:
            return {}

    def create_attribution_mapping(
        self,
        root_nodes: list[Resource],
    ) -> tuple[
        dict[opossum_file.OpossumPackageIdentifier, opossum_file.OpossumPackageModel],
        dict[opossum_file.ResourcePath, list[opossum_file.OpossumPackageIdentifier]],
    ]:
        external_attributions: dict[
            opossum_file.OpossumPackageIdentifier, opossum_file.OpossumPackageModel
        ] = {}
        resources_to_attributions: dict[
            opossum_file.ResourcePath, list[opossum_file.OpossumPackageIdentifier]
        ] = {}

        def process_node(node: Resource) -> None:
            path = _convert_path_to_str(node.path)
            if not path.startswith("/"):
                # the / is required by OpossumUI
                path = "/" + path

            node_attributions_by_id = {
                self.get_attribution_key(a): a.to_opossum_file_format()
                for a in node.attributions
            }
            external_attributions.update(node_attributions_by_id)

            if len(node_attributions_by_id) > 0:
                resources_to_attributions[path] = list(node_attributions_by_id.keys())

            for child in node.children.values():
                process_node(child)

        for root in root_nodes:
            process_node(root)

        return external_attributions, resources_to_attributions

    def get_attribution_key(
        self, attribution: OpossumPackage
    ) -> OpossumPackageIdentifier:
        id = self.attribution_to_id[attribution]
        self.attribution_to_id[attribution] = id
        return id


class ResourceType(Enum):
    FILE = auto()
    FOLDER = auto()


class Resource(BaseModel):
    model_config = ConfigDict(frozen=False, extra="forbid")
    path: PurePath
    type: ResourceType | None = None
    attributions: list[OpossumPackage] = []
    children: dict[str, Resource] = {}

    def to_opossum_file_format(self) -> opossum_file.ResourceInFile:
        if self.children or self.type == ResourceType.FOLDER:
            return {
                _convert_path_to_str(
                    child.path.relative_to(self.path)
                ): child.to_opossum_file_format()
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


class BaseUrlsForSources(BaseModel):
    model_config = ConfigDict(frozen=True, extra="allow")

    def to_opossum_file_format(self) -> opossum_file.BaseUrlsForSourcesModel:
        return opossum_file.BaseUrlsForSourcesModel(**self.model_dump())


class FrequentLicense(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    full_name: str
    short_name: str
    default_text: str

    def to_opossum_file_format(self) -> opossum_file.FrequentLicenseModel:
        return opossum_file.FrequentLicenseModel(
            full_name=self.full_name,
            short_name=self.short_name,
            default_text=self.default_text,
        )


class SourceInfo(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    name: str
    document_confidence: int | float | None = 0
    additional_name: str | None = None

    def to_opossum_file_format(self) -> opossum_file.SourceInfoModel:
        return opossum_file.SourceInfoModel(
            name=self.name,
            document_confidence=self.document_confidence,
            additional_name=self.additional_name,
        )


class OpossumPackage(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    source: SourceInfo
    attribution_confidence: int | None = None
    comment: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    package_namespace: str | None = None
    package_type: str | None = None
    package_purl_appendix: str | None = None
    copyright: str | None = None
    license_name: str | None = None
    license_text: str | None = None
    url: str | None = None
    first_party: bool | None = None
    exclude_from_notice: bool | None = None
    pre_selected: bool | None = None
    follow_up: Literal["FOLLOW_UP"] | None = None
    origin_id: str | None = None
    origin_ids: tuple[str, ...] | None = None
    criticality: Literal["high"] | Literal["medium"] | None = None
    was_preferred: bool | None = None

    def to_opossum_file_format(self) -> opossum_file.OpossumPackageModel:
        return opossum_file.OpossumPackageModel(
            source=self.source.to_opossum_file_format(),
            attribution_confidence=self.attribution_confidence,
            comment=self.comment,
            package_name=self.package_name,
            package_version=self.package_version,
            package_namespace=self.package_namespace,
            package_type=self.package_type,
            package_p_u_r_l_appendix=self.package_purl_appendix,
            copyright=self.copyright,
            license_name=self.license_name,
            license_text=self.license_text,
            url=self.url,
            first_party=self.first_party,
            exclude_from_notice=self.exclude_from_notice,
            pre_selected=self.pre_selected,
            follow_up=self.follow_up,
            origin_id=self.origin_id,
            origin_ids=self.origin_ids,
            criticality=self.criticality,
            was_preferred=self.was_preferred,
        )


class Metadata(BaseModel):
    model_config = ConfigDict(frozen=True, extra="allow")
    project_id: str
    file_creation_date: str
    project_title: str
    project_version: str | None = None
    expected_release_date: str | None = None
    build_date: str | None = None

    def to_opossum_file_format(self) -> opossum_file.MetadataModel:
        return opossum_file.MetadataModel(**self.model_dump())


class ExternalAttributionSource(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    name: str
    priority: int
    is_relevant_for_preferred: bool | None = None

    def to_opossum_file_format(self) -> opossum_file.ExternalAttributionSourceModel:
        return opossum_file.ExternalAttributionSourceModel(
            name=self.name,
            priority=self.priority,
            is_relevant_for_preferred=self.is_relevant_for_preferred,
        )
