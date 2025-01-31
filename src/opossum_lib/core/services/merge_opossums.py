# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

import datetime
import logging
import uuid
from collections import OrderedDict
from collections.abc import Iterable
from pathlib import PurePath

from opossum_lib.core.entities.base_url_for_sources import BaseUrlsForSources
from opossum_lib.core.entities.external_attribution_source import (
    ExternalAttributionSource,
)
from opossum_lib.core.entities.frequent_license import FrequentLicense
from opossum_lib.core.entities.metadata import Metadata
from opossum_lib.core.entities.opossum import (
    Opossum,
    ScanResults,
)
from opossum_lib.core.entities.opossum_package import OpossumPackage
from opossum_lib.core.entities.resource import Resource
from opossum_lib.shared.entities.opossum_output_file_model import OpossumOutputFileModel


def merge_opossums(opossums: list[Opossum]) -> Opossum:
    return Opossum(
        scan_results=_merge_scan_results(opossums),
        review_results=_merge_review_results(opossums),
    )


def _merge_review_results(opossums: list[Opossum]) -> OpossumOutputFileModel | None:
    review_results = None
    for opossum in opossums:
        if opossum.review_results:
            if review_results:
                raise RuntimeError(
                    "More than one input contains review results. "
                    + "Merging thereof is not supported."
                )
            review_results = opossum.review_results
    return review_results


def _merge_scan_results(opossums: list[Opossum]) -> ScanResults:
    scan_results = [opossum.scan_results for opossum in opossums]
    resources = _merge_resources(scan_results)
    unassigned_attributions = _merge_unassigned_attributions(scan_results)
    unassigned_attributions_filtered = _filter_assigned_attributions(
        resources, unassigned_attributions
    )
    return ScanResults(
        metadata=_merge_metadata(scan_results),
        resources=resources,
        attribution_breakpoints=_merge_attribution_breakpoints(scan_results),
        external_attribution_sources=_merge_external_attribution_sources(scan_results),
        frequent_licenses=_merge_frequent_licenses(scan_results),
        files_with_children=_merge_files_with_children(scan_results),
        base_urls_for_sources=_merge_base_urls_for_sources(scan_results),
        attribution_to_id=_merge_attribution_to_id(scan_results),
        unassigned_attributions=unassigned_attributions_filtered,
    )


def _merge_metadata(scan_results: list[ScanResults]) -> Metadata:
    return Metadata(
        project_id=str(uuid.uuid4()),
        project_title="Opossum Merger",
        file_creation_date=datetime.datetime.now().isoformat(),
    )


def _merge_resources(scan_results: list[ScanResults]) -> list[Resource]:
    def add_all(root: Resource, current: Resource) -> None:
        copy = current.model_copy()
        copy.children = {}
        root.add_resource(copy)
        for child in current.children.values():
            add_all(root, child)

    temp_root = Resource(path=PurePath(""))
    for scan_result in scan_results:
        for resource in scan_result.resources:
            add_all(temp_root, resource)

    return list(temp_root.children.values())


def _merge_unique_order_preserving[T](lists: Iterable[list[T]]) -> list[T]:
    full_list = sum(lists, start=[])
    ordered_elements = OrderedDict.fromkeys(full_list).keys()
    return list(ordered_elements)


def _merge_attribution_breakpoints(scan_results: list[ScanResults]) -> list[str]:
    return _merge_unique_order_preserving(
        sr.attribution_breakpoints for sr in scan_results
    )


def _merge_frequent_licenses(scan_results: list[ScanResults]) -> list[FrequentLicense]:
    return _merge_unique_order_preserving(
        sr.frequent_licenses for sr in scan_results if sr.frequent_licenses
    )


def _merge_files_with_children(scan_results: list[ScanResults]) -> list[str]:
    return _merge_unique_order_preserving(
        sr.files_with_children for sr in scan_results if sr.files_with_children
    )


def _merge_dict_no_overwrite[K, V](
    dicts: Iterable[dict[K, V]], *, message: str = ""
) -> dict[K, V]:
    merged: dict[K, V] = {}
    for incoming in dicts:
        for key, val in incoming.items():
            if key in merged and merged[key] != val:
                logging.warning(
                    message
                    + "Overwriting "
                    + f"'{merged[key]}' with '{val}' for key '{key}'",
                )
            merged[key] = val
    return merged


def _merge_base_urls_for_sources(scan_results: list[ScanResults]) -> BaseUrlsForSources:
    merged = _merge_dict_no_overwrite(
        (
            sr.base_urls_for_sources.model_dump()
            for sr in scan_results
            if sr.base_urls_for_sources
        ),
        message="[Merge base Urls for sources]",
    )
    return BaseUrlsForSources(**merged)


def _merge_attribution_to_id(
    scan_results: list[ScanResults],
) -> dict[OpossumPackage, str]:
    return _merge_dict_no_overwrite(
        (sr.attribution_to_id for sr in scan_results),
        message="[Merge attribution to id]",
    )


def _merge_external_attribution_sources(
    scan_results: list[ScanResults],
) -> dict[str, ExternalAttributionSource]:
    return _merge_dict_no_overwrite(
        (sr.external_attribution_sources for sr in scan_results),
        message="[Merge external attribution sources]",
    )


def _merge_unassigned_attributions(
    scan_results: list[ScanResults],
) -> list[OpossumPackage]:
    return _merge_unique_order_preserving(
        sr.unassigned_attributions for sr in scan_results
    )


def _filter_assigned_attributions(
    resources: list[Resource], unassigned_attributions: list[OpossumPackage]
) -> list[OpossumPackage]:
    all_attributions_list = []

    def extract_attributions(resource: Resource) -> None:
        nonlocal all_attributions_list
        all_attributions_list += resource.attributions
        for child in resource.children.values():
            extract_attributions(child)

    for resource in resources:
        extract_attributions(resource)

    all_attributions = set(all_attributions_list)

    return [attr for attr in unassigned_attributions if attr not in all_attributions]
