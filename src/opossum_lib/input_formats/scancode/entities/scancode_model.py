# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict


class ScancodeModel(BaseModel):
    dependencies: list | None = None
    files: list[FileModel]
    license_detections: list[GlobalLicenseDetectionModel] | None = None
    headers: list[HeaderModel]
    packages: list | None = None


class OptionsModel(BaseModel):
    model_config = ConfigDict(extra="allow")
    input: list[str]


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


class ReferenceMatchModel(BaseModel):
    end_line: int
    from_file: str
    license_expression: str
    license_expression_spdx: str
    matched_length: int
    matcher: str
    match_coverage: float
    rule_identifier: str
    rule_relevance: int
    rule_url: Any
    score: float
    start_line: int


class MatchModel(BaseModel):
    end_line: int
    from_file: str
    license_expression: str
    license_expression_spdx: str
    matched_length: int
    matcher: str
    match_coverage: float
    rule_identifier: str
    rule_relevance: int
    rule_url: Any
    score: float
    start_line: int


class GlobalLicenseDetectionModel(BaseModel):
    detection_count: int
    identifier: str
    license_expression: str
    license_expression_spdx: str
    reference_matches: list[ReferenceMatchModel]


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
    authors: list | None = None
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
    for_packages: list | None = None
    holders: list[HolderModel] | None = None
    is_archive: bool | None = None
    is_binary: bool | None = None
    is_media: bool | None = None
    is_script: bool | None = None
    is_source: bool | None = None
    is_text: bool | None = None
    license_clues: list | None = None
    license_detections: list[FileBasedLicenseDetectionModel] | None = None
    md5: str | None = None
    mime_type: str | None = None
    name: str | None = None
    package_data: list | None = None
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
