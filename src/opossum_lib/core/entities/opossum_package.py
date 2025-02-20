#  SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#  #
#  SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from opossum_lib.core.entities.source_info import SourceInfo
from opossum_lib.shared.entities.opossum_input_file_model import OpossumPackageModel


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
    classification: int | None = None
    was_preferred: bool | None = None

    def to_opossum_file_model(self) -> OpossumPackageModel:
        return OpossumPackageModel(
            source=self.source.to_opossum_file_model(),
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
            classification=self.classification,
            was_preferred=self.was_preferred,
        )


class OpossumPackageBuilder:
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

    def __init__(self, source: SourceInfo):
        self.source = source

    def build(self) -> OpossumPackage:
        return OpossumPackage(
            source=self.source,
            attribution_confidence=self.attribution_confidence,
            comment=self.comment,
            package_name=self.package_name,
            package_version=self.package_version,
            package_namespace=self.package_namespace,
            package_type=self.package_type,
            package_purl_appendix=self.package_purl_appendix,
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

    def with_attribution_confidence(
        self, attribution_confidence: int | None
    ) -> OpossumPackageBuilder:
        self.attribution_confidence = attribution_confidence
        return self

    def with_comment(self, comment: str | None) -> OpossumPackageBuilder:
        self.comment = comment
        return self

    def with_package_name(self, package_name: str | None) -> OpossumPackageBuilder:
        self.package_name = package_name
        return self

    def with_package_version(
        self, package_version: str | None
    ) -> OpossumPackageBuilder:
        self.package_version = package_version
        return self

    def with_package_namespace(
        self, package_namespace: str | None
    ) -> OpossumPackageBuilder:
        self.package_namespace = package_namespace
        return self

    def with_package_type(self, package_type: str | None) -> OpossumPackageBuilder:
        self.package_type = package_type
        return self

    def with_package_purl_appendix(
        self, package_purl_appendix: str | None
    ) -> OpossumPackageBuilder:
        self.package_purl_appendix = package_purl_appendix
        return self

    def with_copyright(self, copyright: str | None) -> OpossumPackageBuilder:
        self.copyright = copyright
        return self

    def with_license_name(self, license_name: str | None) -> OpossumPackageBuilder:
        self.license_name = license_name
        return self

    def with_license_text(self, license_text: str | None) -> OpossumPackageBuilder:
        self.license_text = license_text
        return self

    def with_url(self, url: str | None) -> OpossumPackageBuilder:
        self.url = url
        return self

    def with_first_party(self, first_party: bool | None) -> OpossumPackageBuilder:
        self.first_party = first_party
        return self

    def with_exclude_from_notice(
        self, exclude_from_notice: bool | None
    ) -> OpossumPackageBuilder:
        self.exclude_from_notice = exclude_from_notice
        return self

    def with_pre_selected(self, pre_selected: bool | None) -> OpossumPackageBuilder:
        self.pre_selected = pre_selected
        return self

    def with_follow_up(
        self, follow_up: Literal["FOLLOW_UP"] | None
    ) -> OpossumPackageBuilder:
        self.follow_up = follow_up
        return self

    def with_origin_id(self, origin_id: str | None) -> OpossumPackageBuilder:
        self.origin_id = origin_id
        return self

    def with_origin_ids(
        self, origin_ids: tuple[str, ...] | None
    ) -> OpossumPackageBuilder:
        self.origin_ids = origin_ids
        return self

    def with_criticality(
        self, criticality: Literal["high"] | Literal["medium"] | None
    ) -> OpossumPackageBuilder:
        self.criticality = criticality
        return self

    def with_was_preferred(self, was_preferred: bool | None) -> OpossumPackageBuilder:
        self.was_preferred = was_preferred
        return self
