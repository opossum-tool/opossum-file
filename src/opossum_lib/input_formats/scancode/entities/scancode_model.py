# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from enum import Enum

from pydantic import AliasChoices, BaseModel, ConfigDict, Field


class ScancodeModel(BaseModel):
    model_config = ConfigDict(extra="allow")
    files: list[FileModel]
    headers: list[HeaderModel]
    license_references: list[LicenseReferenceModel] | None = None


def to_cli_option(name: str) -> str:
    return "--" + name.replace("_", "-")


class OptionsModel(BaseModel):
    model_config = ConfigDict(
        extra="allow", alias_generator=to_cli_option, populate_by_name=True
    )
    input: list[str] = Field(alias="input")
    strip_root: bool = False
    full_root: bool = False
    copyright: bool = False
    license: bool = False
    package: bool = False
    email: bool = False
    url: bool = False
    info: bool = False
    license_references: bool = False


class HeaderModel(BaseModel):
    end_timestamp: str
    options: OptionsModel


class MatchModel(BaseModel):
    end_line: int
    license_expression_spdx: str = Field(
        validation_alias=AliasChoices(
            "license_expression_spdx", "spdx_license_expression"
        )
    )
    matched_text: str | None = None
    score: float
    start_line: int


class FileBasedLicenseDetectionModel(BaseModel):
    license_expression_spdx: str
    matches: list[MatchModel]


class CopyrightModel(BaseModel):
    copyright: str


class UrlModel(BaseModel):
    start_line: int
    url: str


class FileTypeModel(Enum):
    FILE = "file"
    DIRECTORY = "directory"


class FileModel(BaseModel):
    model_config = ConfigDict(extra="allow")
    copyrights: list[CopyrightModel] | None = None
    for_packages: list[str] | None = None
    is_archive: bool | None = None
    is_binary: bool | None = None
    license_detections: list[FileBasedLicenseDetectionModel] | None = None
    package_data: list[PackageDataModel] | None = None
    path: str
    size: int | None = None
    type: FileTypeModel
    urls: list[UrlModel] | None = None


class PackageDataModel(BaseModel):
    model_config = ConfigDict(extra="allow")
    type: str | None = None
    namespace: str | None = None
    name: str | None = None
    version: str | None = None
    description: str | None = None
    homepage_url: str | None = None
    download_url: str | None = None
    code_view_url: str | None = None
    vcs_url: str | None = None
    copyright: str | None = None
    holder: str | None = None
    declared_license_expression_spdx: str | None = None
    license_detections: list[FileBasedLicenseDetectionModel] | None = None
    other_license_expression_spdx: str | None = None
    notice_text: str | None = None
    dependencies: list[DependencyModel] | None = None
    repository_homepage_url: str | None = None
    purl: str | None = None


class DependencyModel(BaseModel):
    model_config = ConfigDict(extra="allow")
    purl: str | None = None
    scope: str | None = None


class LicenseReferenceModel(BaseModel):
    model_config = ConfigDict(extra="allow")
    spdx_license_key: str
    text: str
