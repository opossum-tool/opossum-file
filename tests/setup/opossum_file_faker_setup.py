# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

from typing import cast

from faker import Faker

from tests.input_formats.opossum.entities.generators.generate_file_information import (
    FileInformationProvider,
    MetadataProvider,
)
from tests.input_formats.opossum.entities.generators.generate_opossum_file_content import (  # noqa: E501
    OpossumFileContentProvider,
)
from tests.input_formats.opossum.entities.generators.generate_outfile_information import (  # noqa: E501
    OpossumOutputFileProvider,
)


## This class serves as a stub to enable tab-completion in the tests and satisfy mypy
class OpossumFileFaker(Faker):
    def __init__(self) -> None:
        opossum_file_content_provider = OpossumFileContentProvider(self)
        opossum_output_file_provider = OpossumOutputFileProvider(self)
        file_information_provider = FileInformationProvider(self)
        metadata_provider = MetadataProvider(self)
        self.opossum_file_content = opossum_file_content_provider.opossum_file_content
        self.output_file = opossum_output_file_provider.output_file
        self.outfile_metadata = opossum_output_file_provider.outfile_metadata
        self.manual_attributions = opossum_output_file_provider.manual_attributions
        self.resources_to_attributions = (
            opossum_output_file_provider.resources_to_attributions
        )
        self.resolved_external_attributions = (
            opossum_output_file_provider.resolved_external_attributions
        )
        self.opossum_file_information = (
            file_information_provider.opossum_file_information
        )
        self.opossum_package = file_information_provider.opossum_package
        self.external_attributions = file_information_provider.external_attributions
        self.attribution_breakpoints = file_information_provider.attribution_breakpoints
        self.external_attribution_sources = (
            file_information_provider.external_attribution_sources
        )
        self.external_attribution_source = (
            file_information_provider.external_attribution_source
        )
        self.opossum_input_metadata = metadata_provider.opossum_input_metadata


def setup_opossum_file_faker(faker: Faker) -> OpossumFileFaker:
    faker.add_provider(OpossumFileContentProvider)
    faker.add_provider(OpossumOutputFileProvider)
    faker.add_provider(FileInformationProvider)
    faker.add_provider(MetadataProvider)
    faker = cast(OpossumFileFaker, faker)
    return faker
