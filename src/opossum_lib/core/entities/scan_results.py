#  SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#  #
#  SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import uuid
from copy import deepcopy

from pydantic import BaseModel, ConfigDict

from opossum_lib.core.entities.base_url_for_sources import BaseUrlsForSources
from opossum_lib.core.entities.config import Config
from opossum_lib.core.entities.external_attribution_source import (
    ExternalAttributionSource,
)
from opossum_lib.core.entities.frequent_license import FrequentLicense
from opossum_lib.core.entities.metadata import Metadata
from opossum_lib.core.entities.opossum_package import OpossumPackage
from opossum_lib.core.entities.root_resource import RootResource
from opossum_lib.shared.entities.opossum_input_file_model import (
    OpossumInputFileModel,
    OpossumPackageIdentifierModel,
    OpossumPackageModel,
    ResourcePathModel,
)


class ScanResults(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    metadata: Metadata
    resources: RootResource = RootResource()
    attribution_breakpoints: list[str] = []
    external_attribution_sources: dict[str, ExternalAttributionSource] = {}
    config: Config = Config()
    frequent_licenses: list[FrequentLicense] = []
    files_with_children: list[str] = []
    base_urls_for_sources: BaseUrlsForSources = BaseUrlsForSources()
    attribution_to_id: dict[OpossumPackage, str] = {}
    unassigned_attributions: set[OpossumPackage] = set()

    def to_opossum_file_model(self) -> OpossumInputFileModel:
        external_attributions, resources_to_attributions = (
            self.create_attribution_mapping(self.resources)
        )
        external_attributions.update(self._get_unassigned_attributions())

        frequent_licenses = None
        if self.frequent_licenses:
            frequent_licenses = [
                license.to_opossum_file_model() for license in self.frequent_licenses
            ]
        base_urls_for_sources = (
            self.base_urls_for_sources
            and self.base_urls_for_sources.to_opossum_file_model()
        )

        external_attribution_sources = {
            key: val.to_opossum_file_model()
            for (key, val) in self.external_attribution_sources.items()
        }

        return OpossumInputFileModel(
            metadata=self.metadata.to_opossum_file_model(),
            resources=self.resources.to_opossum_file_model(),
            external_attributions=external_attributions,
            resources_to_attributions=resources_to_attributions,
            config=self.config.to_opossum_file_model(),
            attribution_breakpoints=deepcopy(self.attribution_breakpoints),
            external_attribution_sources=external_attribution_sources,
            frequent_licenses=frequent_licenses,
            files_with_children=deepcopy(self.files_with_children),
            base_urls_for_sources=base_urls_for_sources,
        )

    def _get_unassigned_attributions(
        self,
    ) -> dict[OpossumPackageIdentifierModel, OpossumPackageModel]:
        if self.unassigned_attributions:
            result = {}
            for unassigned_attribution in self.unassigned_attributions:
                key = self._get_or_create_attribution_id(unassigned_attribution)
                result[key] = unassigned_attribution.to_opossum_file_model()
            return result
        else:
            return {}

    def create_attribution_mapping(
        self,
        resources: RootResource,
    ) -> tuple[
        dict[OpossumPackageIdentifierModel, OpossumPackageModel],
        dict[ResourcePathModel, list[OpossumPackageIdentifierModel]],
    ]:
        external_attributions: dict[
            OpossumPackageIdentifierModel, OpossumPackageModel
        ] = {}
        resources_to_attributions: dict[
            ResourcePathModel, list[OpossumPackageIdentifierModel]
        ] = {}

        for resource in resources.all_resources():
            # OpossumUI always introduces an additional "/" as root
            path = "/" + resource.path.as_posix()
            node_attributions_by_id = {
                self._get_or_create_attribution_id(a): a.to_opossum_file_model()
                for a in resource.attributions
            }
            external_attributions.update(node_attributions_by_id)

            if len(node_attributions_by_id) > 0:
                resources_to_attributions[path] = list(node_attributions_by_id.keys())

        return external_attributions, resources_to_attributions

    def _get_or_create_attribution_id(
        self, attribution: OpossumPackage
    ) -> OpossumPackageIdentifierModel:
        if attribution in self.attribution_to_id:
            id = self.attribution_to_id[attribution]
        else:
            id = str(uuid.uuid4())
        self.attribution_to_id[attribution] = id
        return id
