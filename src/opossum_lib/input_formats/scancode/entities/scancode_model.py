# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from enum import Enum
from typing import Any

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


class SystemEnvironmentModel(BaseModel):
    cpu_architecture: str
    operating_system: str
    platform: str
    platform_version: str
    python_version: str


class ExtraDataModel(BaseModel):
    files_count: int
    spdx_license_list_version: str
    system_environment: SystemEnvironmentModel


class HeaderModel(BaseModel):
    duration: float
    end_timestamp: str
    errors: list
    extra_data: ExtraDataModel
    message: Any
    notice: str
    options: OptionsModel
    output_format_version: str
    start_timestamp: str
    tool_name: str
    tool_version: str
    warnings: list


class MatchModel(BaseModel):
    end_line: int
    from_file: str | None = None
    license_expression: str
    license_expression_spdx: str = Field(
        validation_alias=AliasChoices(
            "license_expression_spdx", "spdx_license_expression"
        )
    )
    matched_length: int
    matched_text: str | None = None
    matcher: str
    match_coverage: float
    rule_identifier: str
    rule_relevance: int
    rule_url: Any
    score: float
    start_line: int


class FileBasedLicenseDetectionModel(BaseModel):
    license_expression: str
    license_expression_spdx: str
    matches: list[MatchModel]
    identifier: str


class CopyrightModel(BaseModel):
    copyright: str
    end_line: int
    start_line: int


class HolderModel(BaseModel):
    end_line: int
    holder: str
    start_line: int


class UrlModel(BaseModel):
    end_line: int
    start_line: int
    url: str


class EmailModel(BaseModel):
    email: str
    end_line: int
    start_line: int


class FileTypeModel(Enum):
    FILE = "file"
    DIRECTORY = "directory"


class FileModel(BaseModel):
    model_config = ConfigDict(extra="allow")
    base_name: str | None = None
    copyrights: list[CopyrightModel] | None = None
    date: str | None = None
    detected_license_expression: str | None = None
    detected_license_expression_spdx: str | None = None
    dirs_count: int | None = None
    emails: list[EmailModel] | None = None
    extension: str | None = None
    files_count: int | None = None
    file_type: str | None = None
    for_packages: list[str] | None = None
    holders: list[HolderModel] | None = None
    is_archive: bool | None = None
    is_binary: bool | None = None
    is_media: bool | None = None
    is_script: bool | None = None
    is_source: bool | None = None
    is_text: bool | None = None
    license_detections: list[FileBasedLicenseDetectionModel] | None = None
    md5: str | None = None
    mime_type: str | None = None
    name: str | None = None
    package_data: list[PackageDataModel] | None = None
    path: str
    percentage_of_license_text: float | None = None
    programming_language: str | None = None
    scan_errors: list[str]
    sha1: str | None = None
    sha256: str | None = None
    size: int | None = None
    size_count: int | None = None
    type: FileTypeModel
    urls: list[UrlModel] | None = None


class PackageDataModel(BaseModel):
    model_config = ConfigDict(extra="allow")
    type: str | None = None
    namespace: str | None = None
    name: str | None = None
    version: str | None = None
    qualifiers: Any = None
    subpath: str | None = None
    primary_language: str | None = None
    description: str | None = None
    release_date: str | None = None
    parties: list | None = None
    keywords: list | None = None
    homepage_url: str | None = None
    download_url: str | None = None
    size: int | None = None
    sha1: str | None = None
    md5: str | None = None
    sha256: str | None = None
    sha512: str | None = None
    bug_tracking_url: str | None = None
    code_view_url: str | None = None
    vcs_url: str | None = None
    copyright: str | None = None
    holder: str | None = None
    declared_license_expression: str | None = None
    declared_license_expression_spdx: str | None = None
    license_detections: list[FileBasedLicenseDetectionModel] | None = None
    other_license_expression: str | None = None
    other_license_expression_spdx: str | None = None
    other_license_detections: list | None = None
    extracted_license_statement: str | None = None
    notice_text: str | None = None
    source_packages: list | None = None
    file_references: list | None = None
    is_private: bool = False
    is_virtual: bool = False
    extra_data: dict[str, Any] | None = None
    dependencies: list[DependencyModel]
    repository_homepage_url: str | None = None
    repository_download_url: str | None = None
    api_data_url: str | None = None
    datasource_id: str | None = None
    purl: str | None = None


class DependencyModel(BaseModel):
    model_config = ConfigDict(extra="allow")
    purl: str | None = None
    extracted_requirement: str | None = None
    scope: str | None = None
    is_runtime: bool = False
    is_optional: bool = False
    is_pinned: bool = Field(
        default=False, validation_alias=AliasChoices("is_pinned", "is_resolved")
    )
    is_direct: bool = False
    resolved_package: Any
    extra_data: Any


class LicenseReferenceModel(BaseModel):
    model_config = ConfigDict(extra="allow")
    key: str
    language: str | None = None
    short_name: str | None = None
    name: str | None = None
    category: str | None = None
    owner: str | None = None
    homepage_url: str | None | None = None
    notes: str | None = None
    is_builtin: bool = False
    is_exception: bool = False
    is_unknown: bool = False
    is_generic: bool = False
    spdx_license_key: str
    other_spdx_license_keys: list[str] | None = None
    osi_license_key: str | None = None
    text_urls: list[str] | None = None
    osi_url: str | None = None
    faq_url: str | None = None
    other_urls: list[str] | None = None
    key_aliases: list[str] | None = None
    minimum_coverage: int | None = None
    standard_notice: str | None = None
    ignorable_copyrights: list[str] | None = None
    ignorable_holders: list[str] | None = None
    ignorable_authors: list[str] | None = None
    ignorable_urls: list[str] | None = None
    ignorable_emails: list[str] | None = None
    text: str
    scancode_url: str | None = None
    licensedb_url: str | None = None
    spdx_url: str | None = None
