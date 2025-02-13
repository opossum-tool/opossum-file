# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

import logging
import sys
import uuid
from collections.abc import Callable
from pathlib import PurePath

from packageurl import PackageURL

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
    SCANCODE_COMMENT_HEADER,
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
    )

    return Opossum(
        scan_results=ScanResults(
            metadata=metadata,
            resources=resources,
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
            purl_data = {}
    else:
        purl_data = {}

    if file.copyrights:
        copyright = "\n".join(c.copyright for c in file.copyrights)
    else:
        copyright = ""
    source_info = SourceInfo(name=SCANCODE_SOURCE_NAME)

    comment = SCANCODE_COMMENT_HEADER
    if file.size == 0:
        comment += "\nFile is empty."
    if file.is_binary:
        comment += "\nFile is binary."
    if file.is_archive:
        comment += "\nFile is an archive."
    if file.urls:
        url_data = "\n".join(f"Line {url.start_line}: {url.url}" for url in file.urls)
        url_comment = f"URLs:\n{url_data}\n"
        comment += "\n" + url_comment

    attribution_infos = []
    if not file.license_detections:
        # generate an empty package to preserve other information
        if copyright or purl_data or comment != SCANCODE_COMMENT_HEADER:
            full_comment = comment + "No license information."
            attribution_infos.append(
                OpossumPackage(
                    source=source_info,
                    copyright=copyright,
                    comment=full_comment,
                    **purl_data,
                )
            )
        return attribution_infos
    for license_detection in file.license_detections:
        license_name = license_detection.license_expression_spdx
        max_score = max(match.score for match in license_detection.matches)
        attribution_confidence = int(max_score)

        reference = license_references.get(license_name)
        text = reference.text if reference else None

        license_data = "\n".join(
            _format_license_match(match) for match in license_detection.matches
        )
        license_comment = f"Detected License(s):\n{license_data}"
        full_comment = comment + "\n" + license_comment

        package = OpossumPackage(
            source=source_info,
            license_name=license_name,
            license_text=text,
            attribution_confidence=attribution_confidence,
            copyright=copyright,
            comment=full_comment,
            **purl_data,
        )
        attribution_infos.append(package)

    return attribution_infos


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
