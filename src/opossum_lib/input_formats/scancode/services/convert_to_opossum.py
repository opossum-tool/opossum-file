# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
import sys
import uuid
from collections.abc import Callable
from datetime import datetime
from pathlib import PurePath
from typing import Self

from packageurl import PackageURL

from opossum_lib.core.entities.external_attribution_source import (
    ExternalAttributionSource,
)
from opossum_lib.core.entities.metadata import Metadata
from opossum_lib.core.entities.opossum import (
    Opossum,
)
from opossum_lib.core.entities.opossum_package import OpossumPackage
from opossum_lib.core.entities.resource import Resource, ResourceType
from opossum_lib.core.entities.root_resource import RootResource
from opossum_lib.core.entities.scan_results import ScanResults
from opossum_lib.core.entities.source_info import SourceInfo
from opossum_lib.input_formats.scancode.constants import (
    SCANCODE_PRIORITY,
    SCANCODE_SOURCE_NAME,
)
from opossum_lib.input_formats.scancode.entities.scancode_model import (
    FileModel,
    FileTypeModel,
    HeaderModel,
    LicenseReference,
    MatchModel,
    ScancodeModel,
)


def convert_to_opossum(scancode_data: ScancodeModel) -> Opossum:
    scancode_header = _extract_scancode_header(scancode_data)
    resources = _extract_opossum_resources(scancode_data)
    metadata = Metadata(
        project_id=str(uuid.uuid4()),
        file_creation_date=scancode_header.end_timestamp,
        project_title="ScanCode file",
        build_date=datetime.now().isoformat(),
    )

    # from Haskell lib
    scancode_source = {
        SCANCODE_SOURCE_NAME: ExternalAttributionSource(
            name="ScanCode", priority=SCANCODE_PRIORITY
        )
    }

    return Opossum(
        scan_results=ScanResults(
            metadata=metadata,
            resources=resources,
            external_attribution_sources=scancode_source,
        )
    )


def _extract_scancode_header(scancode_data: ScancodeModel) -> HeaderModel:
    if len(scancode_data.headers) != 1:
        logging.error("Headers of ScanCode file are invalid.")
        sys.exit(1)
    return scancode_data.headers[0]


def _extract_opossum_resources(scancode_data: ScancodeModel) -> RootResource:
    path_converter = _get_path_converter(scancode_data)
    if scancode_data.license_references:
        license_references = {
            ref.spdx_license_key: ref for ref in scancode_data.license_references
        }
    else:
        license_references = {}
    resources = RootResource()
    for file in scancode_data.files:
        resource = Resource(
            path=path_converter(file.path),
            attributions=_get_attribution_info(file, license_references),
            type=_convert_resource_type(file.type),
        )
        resources.add_resource(resource)

    return resources


def _get_path_converter(scancode_data: ScancodeModel) -> Callable[[str], PurePath]:
    options = scancode_data.headers[0].options
    cli_args = options.model_extra or {}
    if "--strip-root" in cli_args and options.input:
        input_root = PurePath(options.input[0])
        opossum_root = PurePath(input_root.name)
        return lambda path: opossum_root / path
    elif "--full-root" in cli_args and options.input:
        input_root = PurePath(options.input[0]).relative_to("/")
        opossum_root = input_root.parent
        return lambda path: PurePath(path).relative_to(opossum_root)
    else:
        return PurePath


def _convert_resource_type(file_type: FileTypeModel) -> ResourceType:
    if file_type == FileTypeModel.FILE:
        return ResourceType.FILE
    else:
        return ResourceType.FOLDER


def _get_attribution_info(
    file: FileModel, license_references: dict[str, LicenseReference]
) -> list[OpossumPackage]:
    purl_data = _extract_package_data(file)
    copyright = _extract_copyrights(file)
    comment = _create_base_comment(file)

    attribution_infos = []
    license_detections = file.license_detections or []
    if not license_detections and (copyright or purl_data or comment):
        # generate an package without license to preserve other information
        source_info = SourceInfo(name=SCANCODE_SOURCE_NAME, document_confidence=50)
        comment.add("No license information.")
        attribution_infos.append(
            OpossumPackage(
                source=source_info,
                copyright=copyright,
                comment=str(comment),
                **purl_data,
            )
        )
    for license_detection in license_detections:
        license_name = license_detection.license_expression_spdx
        max_score = max(match.score for match in license_detection.matches)
        source_info = SourceInfo(
            name=SCANCODE_SOURCE_NAME, document_confidence=max_score
        )
        attribution_confidence = int(max_score)

        reference = license_references.get(license_name)
        text = reference.text if reference else None

        full_comment = comment.copy()
        license_data = "\n".join(
            _format_license_match(match) for match in license_detection.matches
        )
        license_comment = f"Detected License(s):\n{license_data}"
        full_comment.add(license_comment)

        package = OpossumPackage(
            source=source_info,
            license_name=license_name,
            license_text=text,
            attribution_confidence=attribution_confidence,
            copyright=copyright,
            comment=str(full_comment),
            **purl_data,
        )
        attribution_infos.append(package)

    return attribution_infos


def _extract_copyrights(file: FileModel) -> str:
    if file.copyrights:
        copyright = "\n".join(c.copyright for c in file.copyrights)
    else:
        copyright = ""
    return copyright


def _create_base_comment(file: FileModel) -> CommentBuilder:
    comment = CommentBuilder()
    if file.size == 0:
        comment.add("File is empty.")
    if file.is_binary:
        comment.add("File is binary.")
    if file.is_archive:
        comment.add("File is an archive.")
    if file.urls:
        url_data = "\n".join(f"Line {url.start_line}: {url.url}" for url in file.urls)
        url_comment = f"URLs:\n{url_data}"
        comment.add(url_comment)
    return comment


class CommentBuilder:
    SCANCODE_COMMENT_HEADER = "== ScanCode ==\n"

    def __init__(self, parts: list[str] | None = None) -> None:
        self.parts: list[str] = parts or []

    def add(self, component: str) -> Self:
        self.parts += [component]
        return self

    def copy(self) -> CommentBuilder:
        return CommentBuilder(self.parts[:])

    def __str__(self) -> str:
        body = "\n".join(self.parts)
        return CommentBuilder.SCANCODE_COMMENT_HEADER + "\n" + body

    def __bool__(self) -> bool:
        return bool(self.parts)


def _extract_package_data(file: FileModel) -> dict[str, str | None]:
    purl_data = {}
    if file.for_packages:
        try:
            purl = PackageURL.from_string(file.for_packages[0])
            purl_data = {
                "package_name": purl.name,
                "package_version": purl.version,
                "package_namespace": purl.namespace,
                "package_type": purl.type,
                "package_purl_appendix": f"{purl.qualifiers}#{purl.subpath}",
            }
        except ValueError:
            pass
    return purl_data


def _format_license_match(match: MatchModel) -> str:
    start_line = match.start_line
    end_line = match.end_line
    if start_line == end_line:
        line_str = f"line {start_line}"
    else:
        line_str = f"lines {start_line}-{end_line}"
    license = match.license_expression_spdx
    additional_information = ":\n" + match.matched_text if match.matched_text else ""
    f"Matched {license} in {line_str}{additional_information}"
    return ""
