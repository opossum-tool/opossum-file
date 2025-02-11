# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
from typing import cast

from faker import Faker

from tests.core.entities.generators.external_attribution_source_provider import (
    ExternalAttributionSourceProvider,
)
from tests.core.entities.generators.frequent_license_provider import (
    FrequentLicenseProvider,
)
from tests.core.entities.generators.metadata_provider import MetadataProvider
from tests.core.entities.generators.opossum_provider import OpossumProvider
from tests.core.entities.generators.package_provider import PackageProvider
from tests.core.entities.generators.resource_provider import ResourceProvider
from tests.core.entities.generators.scan_results_provider import ScanResultsProvider
from tests.core.entities.generators.source_info_provider import SourceInfoProvider
from tests.input_formats.opossum.entities.generators.generate_outfile_information import (  # noqa: E501
    OpossumOutputFileProvider,
)


## This class serves as a stub to enable tab-completion in the tests and satisfy mypy
class OpossumFaker(Faker):
    def __init__(self) -> None:
        opossum_provider = OpossumProvider(self)
        scan_results_provider = ScanResultsProvider(self)
        review_result_provider = OpossumOutputFileProvider(self)
        metadata_provider = MetadataProvider(self)
        package_provider = PackageProvider(self)
        resource_provider = ResourceProvider(self)
        external_attribution_source_provider = ExternalAttributionSourceProvider(self)
        frequent_license_provider = FrequentLicenseProvider(self)
        source_info_provider = SourceInfoProvider(self)
        self.opossum = opossum_provider.opossum
        self.scan_results = scan_results_provider.scan_results
        self.attribution_breakpoints = scan_results_provider.attribution_breakpoints
        self.output_file = review_result_provider.output_file
        self.outfile_metadata = review_result_provider.outfile_metadata
        self.manual_attributions = review_result_provider.manual_attributions
        self.resources_to_attributions = (
            review_result_provider.resources_to_attributions
        )
        self.resolved_external_attributions = (
            review_result_provider.resolved_external_attributions
        )
        self.metadata = metadata_provider.metadata
        self.package = package_provider.package
        self.resource = resource_provider.resource
        self.resource_tree = resource_provider.resource_tree
        self.resource_type = resource_provider.resource_type
        self.external_attribution_source = (
            external_attribution_source_provider.external_attribution_source
        )
        self.external_attribution_sources = (
            external_attribution_source_provider.external_attribution_sources
        )
        self.frequent_license = frequent_license_provider.frequent_license
        self.source_info = source_info_provider.source_info


def setup_opossum_faker(faker: Faker) -> OpossumFaker:
    faker.add_provider(OpossumProvider)
    faker.add_provider(ScanResultsProvider)
    faker.add_provider(OpossumOutputFileProvider)
    faker.add_provider(MetadataProvider)
    faker.add_provider(PackageProvider)
    faker.add_provider(ResourceProvider)
    faker.add_provider(ExternalAttributionSourceProvider)
    faker.add_provider(FrequentLicenseProvider)
    faker.add_provider(SourceInfoProvider)
    faker = cast(OpossumFaker, faker)
    return faker
