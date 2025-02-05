# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
import uuid
from typing import Any

from faker.providers import BaseProvider
from faker.providers.file.en_US import Provider as FileProvider
from faker.providers.misc.en_US import Provider as MiscProvider

from opossum_lib.core.entities.base_url_for_sources import BaseUrlsForSources
from opossum_lib.core.entities.external_attribution_source import (
    ExternalAttributionSource,
)
from opossum_lib.core.entities.frequent_license import FrequentLicense
from opossum_lib.core.entities.metadata import Metadata
from opossum_lib.core.entities.opossum_package import OpossumPackage
from opossum_lib.core.entities.resource import Resource, ResourceType
from opossum_lib.core.entities.scan_results import ScanResults
from tests.core.entities.generators.external_attribution_source_provider import (
    ExternalAttributionSourceProvider,
)
from tests.core.entities.generators.frequent_license_provider import (
    FrequentLicenseProvider,
)
from tests.core.entities.generators.metadata_provider import MetadataProvider
from tests.core.entities.generators.package_provider import PackageProvider
from tests.core.entities.generators.resource_provider import ResourceProvider
from tests.shared.generator_helpers import random_list


class ScanResultsProvider(BaseProvider):
    metadata_provider: MetadataProvider
    package_provider: PackageProvider
    misc_provider: MiscProvider
    external_attribution_source_provider: ExternalAttributionSourceProvider
    file_provider: FileProvider
    resource_provider: ResourceProvider
    frequent_license_provider: FrequentLicenseProvider

    def __init__(self, generator: Any) -> None:
        super().__init__(generator)
        self.metadata_provider = MetadataProvider(generator)
        self.package_provider = PackageProvider(generator)
        self.misc_provider = MiscProvider(generator)
        self.external_attribution_source_provider = ExternalAttributionSourceProvider(
            generator
        )
        self.file_provider = FileProvider(generator)
        self.resource_provider = ResourceProvider(generator)
        self.frequent_license_provider = FrequentLicenseProvider(generator)

    def scan_results(
        self,
        metadata: Metadata | None = None,
        resources: list[Resource] | None = None,
        attribution_breakpoints: list[str] | None = None,
        external_attribution_sources: dict[str, ExternalAttributionSource]
        | None = None,
        frequent_licenses: list[FrequentLicense] | None = None,
        files_with_children: list[str] | None = None,
        base_urls_for_sources: BaseUrlsForSources | None = None,
        attribution_to_id: dict[OpossumPackage, str] | None = None,
        unassigned_attributions: list[OpossumPackage] | None = None,
    ) -> ScanResults:
        generated_resources = resources or [self.resource_provider.resource_tree()]
        generated_unassigned_attributions = unassigned_attributions or []
        if unassigned_attributions is None:
            generated_unassigned_attributions = random_list(
                self,
                entry_generator=lambda: self.package_provider.package(),
                min_number_of_entries=0,
            )

        generated_frequent_licenses = frequent_licenses or []
        if frequent_licenses is None:
            generated_frequent_licenses = random_list(
                self,
                self.frequent_license_provider.frequent_license,
                min_number_of_entries=0,
            )
        base_urls_for_sources = base_urls_for_sources or BaseUrlsForSources()
        files_with_children = files_with_children or []
        generated_attribution_to_id: dict[OpossumPackage, str] = attribution_to_id or {}
        if attribution_to_id is None:
            generated_attribution_to_id = self._attribution_to_id(
                generated_resources, generated_unassigned_attributions
            )
        return ScanResults(
            metadata=metadata or self.metadata_provider.metadata(),
            resources=generated_resources,
            attribution_breakpoints=attribution_breakpoints
            or self.attribution_breakpoints(),
            external_attribution_sources=external_attribution_sources
            or self.external_attribution_source_provider.external_attribution_sources(),
            frequent_licenses=generated_frequent_licenses,
            files_with_children=files_with_children,
            base_urls_for_sources=base_urls_for_sources,
            unassigned_attributions=generated_unassigned_attributions,
            attribution_to_id=generated_attribution_to_id,
        )

    def _attribution_to_id(
        self,
        resources: list[Resource] | None,
        unassigned_attributions: list[OpossumPackage] | None,
    ) -> dict[OpossumPackage, str]:
        attributions = []

        def get_attributions_from_resource_tree(
            resource: Resource,
        ) -> list[OpossumPackage]:
            attributions: list[OpossumPackage] = resource.attributions
            for child in resource.children.values():
                if resource.type == ResourceType.FILE:
                    attributions += child.attributions
                else:
                    attributions += get_attributions_from_resource_tree(child)
            return attributions

        if resources:
            for resource in resources:
                attributions += get_attributions_from_resource_tree(resource)

        if unassigned_attributions:
            attributions += unassigned_attributions

        return {attribution: str(uuid.uuid4()) for attribution in attributions}

    def attribution_breakpoints(self, max_nb_of_breakpoints: int = 5) -> list[str]:
        nb_of_breakpoints = self.random_int(1, max_nb_of_breakpoints)
        return [
            self.file_provider.file_path(extension=[], depth=3)
            for _ in range(nb_of_breakpoints)
        ]
