# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

from copy import deepcopy
from pathlib import PurePath

from opossum_lib.core.entities.base_url_for_sources import BaseUrlsForSources
from opossum_lib.core.entities.external_attribution_source import (
    ExternalAttributionSource,
)
from opossum_lib.core.entities.frequent_license import FrequentLicense
from opossum_lib.core.entities.metadata import Metadata
from opossum_lib.core.entities.opossum import (
    Opossum,
)
from opossum_lib.core.entities.opossum_package import OpossumPackage
from opossum_lib.core.entities.resource import (
    Resource,
    ResourceType,
    _convert_path_to_str,
)
from opossum_lib.core.entities.scan_results import ScanResults
from opossum_lib.core.entities.source_info import SourceInfo
from opossum_lib.shared.entities.opossum_file_model import OpossumFileModel
from opossum_lib.shared.entities.opossum_input_file_model import (
    BaseUrlsForSourcesModel,
    FrequentLicenseModel,
    MetadataModel,
    OpossumInputFileModel,
    OpossumPackageIdentifierModel,
    OpossumPackageModel,
    ResourceInFileModel,
    ResourcePathModel,
    SourceInfoModel,
)
from opossum_lib.shared.entities.opossum_input_file_model import (
    ExternalAttributionSourceModel as FileExternalAttributionSource,
)


def convert_to_opossum(opossum_file_model: OpossumFileModel) -> Opossum:
    opossum = Opossum(
        scan_results=_convert_to_scan_results(opossum_file_model.input_file),
        review_results=opossum_file_model.output_file,
    )
    return opossum


def _convert_to_scan_results(
    opossum_input_file_model: OpossumInputFileModel,
) -> ScanResults:
    resources, used_attribution_ids = _convert_to_resource_tree(
        resources=opossum_input_file_model.resources,
        external_attributions=opossum_input_file_model.external_attributions,
        resources_to_attributions=opossum_input_file_model.resources_to_attributions,
    )
    frequent_licenses_normalized = opossum_input_file_model.frequent_licenses or []
    frequent_licenses = _convert_frequent_licenses(frequent_licenses_normalized)

    base_urls_for_sources_normalized = (
        opossum_input_file_model.base_urls_for_sources or BaseUrlsForSourcesModel()
    )
    base_urls_for_sources = BaseUrlsForSources(
        **(base_urls_for_sources_normalized.model_dump())
    )

    file_attribution_sources = opossum_input_file_model.external_attribution_sources
    external_attribution_sources = {
        name: _convert_external_attribution_source(attribution_source)
        for name, attribution_source in file_attribution_sources.items()
    }

    attribution_with_id = _convert_to_attribution_with_id(
        opossum_input_file_model.external_attributions
    )
    return ScanResults(
        metadata=_convert_to_metadata(opossum_input_file_model.metadata),
        resources=resources,
        attribution_breakpoints=deepcopy(
            opossum_input_file_model.attribution_breakpoints
        ),
        external_attribution_sources=external_attribution_sources,
        frequent_licenses=frequent_licenses,
        files_with_children=deepcopy(
            opossum_input_file_model.files_with_children or []
        ),
        base_urls_for_sources=base_urls_for_sources,
        attribution_to_id=attribution_with_id,
        unassigned_attributions=_get_unassigned_attributions(
            used_attribution_ids, opossum_input_file_model.external_attributions
        ),
    )


def _get_unassigned_attributions(
    used_attribution_ids: set[OpossumPackageIdentifierModel],
    external_attributions: dict[
        OpossumPackageIdentifierModel,
        OpossumPackageModel,
    ],
) -> list[OpossumPackage] | None:
    available_attribution_ids = external_attributions.keys()
    unused_attributions_ids = set(available_attribution_ids) - used_attribution_ids
    unused_attributions = [
        _convert_package(external_attributions[id]) for id in unused_attributions_ids
    ]
    return unused_attributions


def _convert_external_attribution_source(
    external_attribution_source: FileExternalAttributionSource,
) -> ExternalAttributionSource:
    return ExternalAttributionSource(
        name=external_attribution_source.name,
        priority=external_attribution_source.priority,
        is_relevant_for_preferred=external_attribution_source.is_relevant_for_preferred,
    )


def _convert_frequent_licenses(
    frequent_licenses_infile: list[FrequentLicenseModel],
) -> list[FrequentLicense]:
    frequent_licenses: list[FrequentLicense] = [
        _convert_frequent_license(license) for license in frequent_licenses_infile
    ]
    return frequent_licenses


def _convert_to_metadata(
    infile_metadata: MetadataModel,
) -> Metadata:
    return Metadata(**infile_metadata.model_dump())


def _convert_to_resource_tree(
    resources: ResourceInFileModel,
    external_attributions: dict[
        OpossumPackageIdentifierModel,
        OpossumPackageModel,
    ],
    resources_to_attributions: dict[
        ResourcePathModel,
        list[OpossumPackageIdentifierModel],
    ],
) -> tuple[list[Resource], set[OpossumPackageIdentifierModel]]:
    used_attribution_ids = set()

    def generate_child_resource(
        current_path: PurePath,
        to_insert: ResourceInFileModel,
    ) -> Resource:
        path = current_path
        current_path_as_string = _convert_path_to_str(current_path)
        if not current_path_as_string.startswith("/"):
            current_path_as_string = "/" + current_path_as_string
        attributions, attribution_ids = _get_applicable_attributions(
            current_path_as_string
        )
        used_attribution_ids.update(attribution_ids)
        if isinstance(to_insert, int):
            resource_type = ResourceType.FILE
            return Resource(
                type=resource_type,
                path=path,
                attributions=attributions,
            )
        else:
            resource_type = ResourceType.FOLDER
            return Resource(
                type=resource_type,
                path=path,
                attributions=attributions,
                children={
                    relative_path: generate_child_resource(
                        current_path / relative_path, child
                    )
                    for relative_path, child in to_insert.items()
                },
            )

    def _get_applicable_attributions(
        current_path_as_string: str,
    ) -> tuple[list[OpossumPackage], set[OpossumPackageIdentifierModel]]:
        attributions = []
        attribution_ids: list[str] = []
        if current_path_as_string in resources_to_attributions:
            attribution_ids = resources_to_attributions[current_path_as_string]
            attributions = [
                _convert_package(external_attributions[id]) for id in attribution_ids
            ]
        return attributions, set(attribution_ids)

    root_path = PurePath("")

    if isinstance(resources, dict):
        return [
            generate_child_resource(root_path / relative_path, child)
            for relative_path, child in resources.items()
        ], used_attribution_ids
    else:
        raise RuntimeError("Root node must not be of file type")


def _convert_to_attribution_with_id(
    external_attributions: dict[
        OpossumPackageIdentifierModel,
        OpossumPackageModel,
    ],
) -> dict[OpossumPackage, str]:
    result = {}
    for package_identifier, package in external_attributions.items():
        converted_package = _convert_package(package)
        if converted_package not in result:
            result[converted_package] = package_identifier
        else:
            raise RuntimeError(
                "An attribution was duplicated in the scan breaking internal assertions"
            )
    return result


def _convert_frequent_license(
    infile_frequent_license: FrequentLicenseModel,
) -> FrequentLicense:
    return FrequentLicense(
        full_name=infile_frequent_license.full_name,
        short_name=infile_frequent_license.short_name,
        default_text=infile_frequent_license.default_text,
    )


def _convert_package(
    infile_package: OpossumPackageModel,
) -> OpossumPackage:
    return OpossumPackage(
        source=_convert_source(infile_package.source),
        attribution_confidence=infile_package.attribution_confidence,
        comment=infile_package.comment,
        package_name=infile_package.package_name,
        package_version=infile_package.package_version,
        package_namespace=infile_package.package_namespace,
        package_type=infile_package.package_type,
        package_purl_appendix=infile_package.package_p_u_r_l_appendix,
        copyright=infile_package.copyright,
        license_name=infile_package.license_name,
        license_text=infile_package.license_text,
        url=infile_package.url,
        first_party=infile_package.first_party,
        exclude_from_notice=infile_package.exclude_from_notice,
        pre_selected=infile_package.pre_selected,
        follow_up=infile_package.follow_up,
        origin_id=infile_package.origin_id,
        origin_ids=infile_package.origin_ids,
        criticality=infile_package.criticality,
        was_preferred=infile_package.was_preferred,
    )


def _convert_source(
    infile_source_info: SourceInfoModel,
) -> SourceInfo:
    return SourceInfo(
        name=infile_source_info.name,
        document_confidence=infile_source_info.document_confidence,
        additional_name=infile_source_info.additional_name,
    )
