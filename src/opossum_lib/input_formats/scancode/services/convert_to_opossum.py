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
    DependencyModel,
    FileModel,
    FileTypeModel,
    HeaderModel,
    LicenseReferenceModel,
    MatchModel,
    PackageDataModel,
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
    file: FileModel, license_references: dict[str, LicenseReferenceModel]
) -> list[OpossumPackage]:
    attribution_infos = _create_attributions_from_license_detections(
        file, license_references
    )

    package_data = file.package_data or []
    for package in package_data:
        package_attribution = _create_package_attribution(package, license_references)
        attribution_infos.append(package_attribution)

        dependencies = package.dependencies or []
        for dependency in dependencies:
            dependency_attribution = _create_dependency_attribution(
                dependency, package_attribution.package_name
            )
            attribution_infos.append(dependency_attribution)

    return attribution_infos


def _create_attributions_from_license_detections(
    file: FileModel, license_references: dict[str, LicenseReferenceModel]
) -> list[OpossumPackage]:
    purl_data = _extract_package_data(file.for_packages[0]) if file.for_packages else {}
    copyright = _extract_copyrights(file)
    comment = _create_base_comment(file)
    if not file.license_detections and (copyright or purl_data or comment):
        # generate an package without license to preserve other information
        source_info = SourceInfo(name=SCANCODE_SOURCE_NAME, document_confidence=50)
        full_comment = comment.copy().add("No license information.")
        return [
            OpossumPackage(
                source=source_info,
                copyright=copyright,
                comment=str(full_comment),
                **purl_data,
            )
        ]
    attribution_infos = []
    for license_detection in file.license_detections or []:
        license_name = license_detection.license_expression_spdx
        max_score = max(match.score for match in license_detection.matches)
        source_info = SourceInfo(
            name=SCANCODE_SOURCE_NAME, document_confidence=int(max_score)
        )

        reference = license_references.get(license_name)
        text = reference.text if reference else None

        license_data = "\n".join(
            _format_license_match(match) for match in license_detection.matches
        )
        license_comment = f"Detected License(s):\n{license_data}"
        full_comment = comment.copy().add(license_comment)

        license_attribution = OpossumPackage(
            source=source_info,
            license_name=license_name,
            license_text=text,
            attribution_confidence=int(max_score),
            copyright=copyright,
            comment=str(full_comment),
            **purl_data,
        )
        attribution_infos.append(license_attribution)
    return attribution_infos


def _create_package_attribution(
    package: PackageDataModel, license_references: dict[str, LicenseReferenceModel]
) -> OpossumPackage:
    purl_data = _extract_package_data(package.purl) if package.purl else {}
    purl_data["package_name"] = purl_data.get("package_name", package.name)
    purl_data["package_type"] = purl_data.get("package_name", package.type)
    purl_data["package_namespace"] = purl_data.get("package_name", package.namespace)
    purl_data["package_version"] = purl_data.get("package_version", package.version)
    url = (
        package.homepage_url
        or package.repository_homepage_url
        or package.download_url
        or package.code_view_url
        or package.vcs_url
        or package.download_url
    )
    if package.license_detections:
        all_matches = sum(
            (detection.matches for detection in package.license_detections), start=[]
        )
        confidence = (
            int(max(match.score for match in all_matches)) if all_matches else None
        )
    else:
        confidence = None
    license_name = (
        package.declared_license_expression_spdx
        or package.other_license_expression_spdx
    )
    reference = license_references.get(license_name) if license_name else None
    license_text = reference.text if reference else None

    comment = CommentBuilder()
    comment.add("Created from package detection")
    if package.type:
        comment.add("Type: " + package.type)
    if package.description:
        comment.add("Description:\n" + package.description)
    if package.notice_text:
        comment.add("Notice:\n" + package.notice_text)
    return OpossumPackage(
        source=SourceInfo(name=SCANCODE_SOURCE_NAME),
        attribution_confidence=confidence,
        copyright=package.copyright or package.holder,
        license_name=license_name,
        license_text=license_text,
        url=url,
        comment=str(comment),
        **purl_data,
    )


def _create_dependency_attribution(
    dependency: DependencyModel, parent: str | None
) -> OpossumPackage:
    purl_data = _extract_package_data(dependency.purl) if dependency.purl else {}
    comment = CommentBuilder()
    if parent:
        comment.add("Dependency of " + parent)
    else:
        comment.add("Detected as dependency")
    if dependency.scope:
        comment.add("Scope: " + dependency.scope)
    return OpossumPackage(
        source=SourceInfo(name=SCANCODE_SOURCE_NAME, document_confidence=50),
        comment=str(comment),
        **purl_data,
    )


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
    SCANCODE_COMMENT_HEADER = "== ScanCode =="

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


def _extract_package_data(purl_str: str) -> dict[str, str | None]:
    try:
        purl = PackageURL.from_string(purl_str)
        return {
            "package_name": purl.name,
            "package_version": purl.version,
            "package_namespace": purl.namespace,
            "package_type": purl.type,
            "package_purl_appendix": f"{purl.qualifiers}#{purl.subpath}",
        }
    except ValueError:
        return {}


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
