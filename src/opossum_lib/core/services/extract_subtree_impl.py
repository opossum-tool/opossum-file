# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0


import logging
from pathlib import PurePath, PurePosixPath

from opossum_lib.core.entities.opossum import Opossum
from opossum_lib.core.entities.root_resource import RootResource
from opossum_lib.core.entities.scan_results import ScanResults
from opossum_lib.shared.entities.opossum_output_file_model import OpossumOutputFileModel


def extract_subtree_impl(opossum: Opossum, subpath: PurePath) -> Opossum:
    if subpath.is_absolute():
        subpath = PurePosixPath(*subpath.parts[1:])
    if not isinstance(subpath, PurePosixPath):
        subpath = PurePosixPath(subpath)

    new_scan_results = _extract_scan_results(opossum, subpath)

    new_review_results = _filter_review_results(
        opossum.review_results, new_scan_results, subpath
    )

    return Opossum(scan_results=new_scan_results, review_results=new_review_results)


def _extract_scan_results(opossum: Opossum, subpath: PurePosixPath) -> ScanResults:
    new_root_resource = RootResource()
    for child_resource in opossum.scan_results.resources.all_resources():
        if child_resource.path.is_relative_to(subpath):
            new_path = child_resource.path.relative_to(subpath.parent)
            new_resource = child_resource.model_copy(
                update={"path": new_path, "children": {}}
            )
            new_root_resource.add_resource(new_resource)
    if not new_root_resource.children:
        logging.warning("No children found for the specified subpath.")

    new_attribution_breakpoints = [
        path
        for path in opossum.scan_results.attribution_breakpoints
        if PurePath(path).is_relative_to(subpath)
    ]
    new_files_with_children = [
        path
        for path in opossum.scan_results.files_with_children
        if PurePath(path).is_relative_to(subpath)
    ]

    kept_attributions = set()
    for resource in new_root_resource.all_resources():
        kept_attributions |= set(resource.attributions)
    new_attribution_to_id = {
        attribution: id
        for (attribution, id) in opossum.scan_results.attribution_to_id.items()
        if attribution in kept_attributions
    }

    new_scan_results = ScanResults(
        metadata=opossum.scan_results.metadata,
        resources=new_root_resource,
        attribution_breakpoints=new_attribution_breakpoints,
        external_attribution_sources=opossum.scan_results.external_attribution_sources,
        config=opossum.scan_results.config,
        frequent_licenses=opossum.scan_results.frequent_licenses,
        files_with_children=new_files_with_children,
        base_urls_for_sources=opossum.scan_results.base_urls_for_sources,
        attribution_to_id=new_attribution_to_id,
        unassigned_attributions=opossum.scan_results.unassigned_attributions,
    )

    return new_scan_results


def _filter_review_results(
    old_review_results: OpossumOutputFileModel | None,
    new_scan_results: ScanResults,
    subpath: PurePosixPath,
) -> OpossumOutputFileModel | None:
    if not old_review_results:
        return None
    new_metadata = old_review_results.metadata.model_copy(
        update={"input_file_md5_checksum": None}
    )

    absolute_subpath = "/" / subpath
    # the paths used as keys for  manual_attributions include a leading "/"
    new_manual_attributions = {
        path: attributions
        for (path, attributions) in old_review_results.manual_attributions.items()
        if PurePosixPath(path).is_relative_to(absolute_subpath)
    }
    new_resources_to_attributions = {
        path: attributions
        for (path, attributions) in old_review_results.resources_to_attributions.items()
        if PurePosixPath(path).is_relative_to(absolute_subpath)
    }

    # since we loaded an Opossum file, every resource has a preexisting ID and thus
    # new_scan_results.attribution_to_id contains the ID of each resource
    # in new_scan_results
    if old_review_results.resolved_external_attributions:
        all_attributions = set(new_scan_results.attribution_to_id.values())
        new_resolved_external_attributions = [
            attributionID
            for attributionID in old_review_results.resolved_external_attributions
            if attributionID in all_attributions
        ]
    else:
        new_resolved_external_attributions = None
    new_review_results = OpossumOutputFileModel(
        metadata=new_metadata,
        manual_attributions=new_manual_attributions,
        resources_to_attributions=new_resources_to_attributions,
        resolved_external_attributions=new_resolved_external_attributions,
    )
    return new_review_results
