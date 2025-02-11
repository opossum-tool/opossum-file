# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

import logging
import sys
import uuid
from pathlib import PurePath

from opossum_lib.core.entities.metadata import Metadata
from opossum_lib.core.entities.opossum import (
    Opossum,
)
from opossum_lib.core.entities.opossum_package import OpossumPackage
from opossum_lib.core.entities.resource import Resource, ResourceType, TopLevelResource
from opossum_lib.core.entities.scan_results import ScanResults
from opossum_lib.core.entities.source_info import SourceInfo
from opossum_lib.input_formats.scancode.constants import SCANCODE_SOURCE_NAME
from opossum_lib.input_formats.scancode.entities.scancode_model import (
    FileModel,
    FileTypeModel,
    HeaderModel,
    ScancodeModel,
)


def convert_to_opossum(scancode_data: ScancodeModel) -> Opossum:
    resources = _extract_opossum_resources(scancode_data)

    scancode_header = _extract_scancode_header(scancode_data)
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


def _extract_opossum_resources(
    scancode_data: ScancodeModel,
) -> TopLevelResource:
    resources = TopLevelResource()
    for file in scancode_data.files:
        resource = Resource(
            path=PurePath(file.path),
            attributions=_get_attribution_info(file),
            type=_convert_resource_type(file.type),
        )
        resources.add_resource(resource)

    return resources


def _convert_resource_type(file_type: FileTypeModel) -> ResourceType:
    if file_type == FileTypeModel.FILE:
        return ResourceType.FILE
    else:
        return ResourceType.FOLDER


def _get_attribution_info(file: FileModel) -> list[OpossumPackage]:
    if file.type == FileTypeModel.DIRECTORY:
        return []
    copyright = "\n".join(c.copyright for c in file.copyrights)
    source_info = SourceInfo(name=SCANCODE_SOURCE_NAME)

    attribution_infos = []
    for license_detection in file.license_detections:
        license_name = license_detection.license_expression_spdx
        max_score = max(m.score for m in license_detection.matches)
        attribution_confidence = int(max_score)

        package = OpossumPackage(
            source=source_info,
            license_name=license_name,
            attribution_confidence=attribution_confidence,
            copyright=copyright,
        )
        attribution_infos.append(package)

    return attribution_infos
