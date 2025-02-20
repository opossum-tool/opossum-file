# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import field
from typing import Literal

from pydantic import ConfigDict, model_serializer

from opossum_lib.shared.entities.camel_base_model import CamelBaseModel

type OpossumPackageIdentifierModel = str
type ResourcePathModel = str
type ResourceInFileModel = dict[str, ResourceInFileModel] | int


class OpossumInputFileModel(CamelBaseModel):
    metadata: MetadataModel
    resources: ResourceInFileModel
    external_attributions: dict[OpossumPackageIdentifierModel, OpossumPackageModel]
    resources_to_attributions: dict[
        ResourcePathModel, list[OpossumPackageIdentifierModel]
    ]
    config: ConfigModel | None = None
    attribution_breakpoints: list[str] = field(default_factory=list)
    external_attribution_sources: dict[str, ExternalAttributionSourceModel] = field(
        default_factory=dict
    )
    frequent_licenses: list[FrequentLicenseModel] | None = None
    files_with_children: list[str] | None = None
    base_urls_for_sources: BaseUrlsForSourcesModel | None = None


class BaseUrlsForSourcesModel(CamelBaseModel):
    @model_serializer
    def serialize(self) -> dict:
        # hack to override not serializing keys with corresponding value none:
        # In this case this is valid and should be part of the serialization
        return {k: v for k, v in self}

    model_config = ConfigDict(extra="allow")


class ConfigModel(CamelBaseModel):
    model_config = ConfigDict(extra="allow")
    classifications: dict[int, str] | None = None


class FrequentLicenseModel(CamelBaseModel):
    full_name: str
    short_name: str
    default_text: str


class SourceInfoModel(CamelBaseModel):
    name: str
    document_confidence: int | float | None = 0
    additional_name: str | None = None


class OpossumPackageModel(CamelBaseModel):
    source: SourceInfoModel
    attribution_confidence: int | None = None
    comment: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    package_namespace: str | None = None
    package_type: str | None = None
    package_p_u_r_l_appendix: str | None = None
    copyright: str | None = None
    license_name: str | None = None
    license_text: str | None = None
    url: str | None = None
    first_party: bool | None = None
    exclude_from_notice: bool | None = None
    pre_selected: bool | None = None
    follow_up: Literal["FOLLOW_UP"] | None = None
    origin_id: str | None = None
    origin_ids: list[str] | None = None
    criticality: Literal["high"] | Literal["medium"] | None = None
    classification: int | None = None
    was_preferred: bool | None = None


class MetadataModel(CamelBaseModel):
    model_config = ConfigDict(extra="allow")
    project_id: str
    file_creation_date: str
    project_title: str
    project_version: str | None = None
    expected_release_date: str | None = None
    build_date: str | None = None


class ExternalAttributionSourceModel(CamelBaseModel):
    model_config = ConfigDict(frozen=True)
    name: str
    priority: int
    is_relevant_for_preferred: bool | None = None
