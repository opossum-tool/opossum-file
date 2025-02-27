# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os.path
import uuid
from collections.abc import Callable
from datetime import datetime
from pathlib import PurePath
from typing import Self
from urllib.parse import urlencode

from packageurl import PackageURL
from pydantic import BaseModel

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
    SCANCODE_DEPENDENCY_PRIORITY,
    SCANCODE_PACKAGE_PRIORITY,
    SCANCODE_PRIORITY,
    SCANCODE_SOURCE_NAME,
    SCANCODE_SOURCE_NAME_DEPENDENCY,
    SCANCODE_SOURCE_NAME_PACKAGE,
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

    return Opossum(
        scan_results=ScanResults(
            metadata=_generate_metadata(scancode_header),
            resources=_extract_opossum_resources(scancode_data),
            external_attribution_sources=_get_external_attribution_sources(),
        )
    )


def _get_external_attribution_sources() -> dict[str, ExternalAttributionSource]:
    return {
        SCANCODE_SOURCE_NAME: ExternalAttributionSource(
            name="ScanCode", priority=SCANCODE_PRIORITY
        ),
        SCANCODE_SOURCE_NAME_PACKAGE: ExternalAttributionSource(
            name="ScanCode Package", priority=SCANCODE_PACKAGE_PRIORITY
        ),
        SCANCODE_SOURCE_NAME_DEPENDENCY: ExternalAttributionSource(
            name="ScanCode Dependency", priority=SCANCODE_DEPENDENCY_PRIORITY
        ),
    }


def _generate_metadata(scancode_header: HeaderModel) -> Metadata:
    return Metadata(
        project_id=str(uuid.uuid4()),
        file_creation_date=scancode_header.end_timestamp,
        project_title="ScanCode file",
        build_date=datetime.now().isoformat(),
    )


def _extract_scancode_header(scancode_data: ScancodeModel) -> HeaderModel:
    if len(scancode_data.headers) != 1:
        raise RuntimeError("Headers of ScanCode file are invalid.")
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
    input_paths = [PurePath(input) for input in options.input or []]
    common_root = PurePath(os.path.commonpath(input_paths))
    if options.strip_root:
        opossum_root = PurePath(common_root.name)
        return lambda path: opossum_root / path
    elif options.full_root:
        if common_root.is_absolute():
            # Scancode files always have relative paths.
            # In this case relative to root, so we need to remove the root part
            print(common_root)
            common_root = PurePath(*common_root.parts[1:])
            print(common_root)
        opossum_root = common_root.parent
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

    for package in file.package_data or []:
        package_attribution = _create_package_attribution(package, license_references)
        attribution_infos.append(package_attribution)

        for dependency in package.dependencies or []:
            dependency_attribution = _create_dependency_attribution(
                dependency, package_attribution.package_name
            )
            attribution_infos.append(dependency_attribution)

    return attribution_infos


def _create_attributions_from_license_detections(
    file: FileModel, license_references: dict[str, LicenseReferenceModel]
) -> list[OpossumPackage]:
    purl_data = (
        _extract_purl_data(file.for_packages[0]) if file.for_packages else PURLData()
    )
    copyright = _extract_copyrights(file)
    comment = _create_base_comment(file)

    if not file.license_detections and (copyright or purl_data or comment):
        # generate a package without license to preserve other information
        source_info = SourceInfo(name=SCANCODE_SOURCE_NAME, document_confidence=50)
        full_comment = comment.copy().add("No license information.")
        return [
            OpossumPackage(
                source=source_info,
                copyright=copyright,
                comment=str(full_comment),
                **purl_data.model_dump(),
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

        attribution_infos.append(
            OpossumPackage(
                source=source_info,
                license_name=license_name,
                license_text=text,
                attribution_confidence=int(max_score),
                copyright=copyright,
                comment=str(full_comment),
                **purl_data.model_dump(),
            )
        )
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


class PURLData(BaseModel):
    package_name: str | None = None
    package_version: str | None = None
    package_namespace: str | None = None
    package_type: str | None = None
    package_purl_appendix: str | None = None

    def __bool__(self) -> bool:
        return bool(self.model_dump(exclude_none=True))


def _extract_purl_data(purl_str: str | None) -> PURLData:
    if not purl_str:
        return PURLData()
    try:
        purl = PackageURL.from_string(purl_str)
    except ValueError:
        return PURLData()
    if not purl.qualifiers:
        qualifiers = ""
    elif isinstance(purl.qualifiers, str):
        qualifiers = purl.qualifiers
    else:
        qualifiers = urlencode(purl.qualifiers)
    data = PURLData()
    appendix = "#".join(piece for piece in (qualifiers, purl.subpath) if piece)
    data.package_name = purl.name
    data.package_version = purl.version
    data.package_namespace = purl.namespace
    data.package_type = purl.type
    data.package_purl_appendix = appendix
    return data


def _create_package_attribution(
    package: PackageDataModel, license_references: dict[str, LicenseReferenceModel]
) -> OpossumPackage:
    def _get_basic_package_information() -> PURLData:
        purl_data = _extract_purl_data(package.purl)
        purl_data.package_name = purl_data.package_name or package.name
        purl_data.package_type = purl_data.package_type or package.type
        purl_data.package_namespace = purl_data.package_namespace or package.namespace
        purl_data.package_version = purl_data.package_version or package.version
        return purl_data

    def _get_url_for_package() -> str | None:
        return (
            package.homepage_url
            or package.repository_homepage_url
            or package.download_url
            or package.code_view_url
            or package.vcs_url
            or package.download_url
        )

    def _get_attribution_confidence() -> int | None:
        if package.license_detections:
            all_scores = (
                match.score
                for detection in package.license_detections
                for match in detection.matches
            )
            return int(max(all_scores))
        else:
            return None

    def _get_text_for_license(license_name: str | None) -> str | None:
        reference = license_references.get(license_name) if license_name else None
        return reference.text if reference else None

    def _create_comment_for_package() -> str:
        comment = CommentBuilder()
        comment.add("Created from package detection")
        if package.type:
            comment.add("Type: " + package.type)
        if package.description:
            comment.add("Description:\n" + package.description)
        if package.notice_text:
            comment.add("Notice:\n" + package.notice_text)
        return str(comment)

    license_name = (
        package.declared_license_expression_spdx
        or package.other_license_expression_spdx
    )
    return OpossumPackage(
        source=SourceInfo(name=SCANCODE_SOURCE_NAME_PACKAGE),
        attribution_confidence=_get_attribution_confidence(),
        comment=_create_comment_for_package(),
        copyright=package.copyright or package.holder,
        license_name=license_name,
        license_text=_get_text_for_license(license_name),
        url=_get_url_for_package(),
        **_get_basic_package_information().model_dump(),
    )


def _create_dependency_attribution(
    dependency: DependencyModel, parent: str | None
) -> OpossumPackage:
    purl_data = _extract_purl_data(dependency.purl)
    comment = CommentBuilder()
    if parent:
        comment.add("Dependency of " + parent)
    else:
        comment.add("Detected as dependency")
    if dependency.scope:
        comment.add("Scope: " + dependency.scope)
    return OpossumPackage(
        source=SourceInfo(name=SCANCODE_SOURCE_NAME_DEPENDENCY, document_confidence=50),
        comment=str(comment),
        **purl_data.model_dump(),
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
