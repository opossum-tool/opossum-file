# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

from collections.abc import Sequence
from typing import Any, cast

from faker import Faker, Generator

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


class OpossumFileFaker(Faker):
    file_information_provider: FileInformationProvider
    metadata_provider: MetadataProvider
    opossum_output_file_provider: OpossumOutputFileProvider
    opossum_file_content_provider: OpossumFileContentProvider

    def __init__(
        self,
        locale: str | Sequence[str] | dict[str, int | float] | None = None,
        providers: list[str] | None = None,
        generator: Generator | None = None,
        includes: list[str] | None = None,
        use_weighting: bool = True,
        **config: Any,
    ):
        super().__init__(
            locale, providers, generator, includes, use_weighting, **config
        )
        self.file_information_provider = FileInformationProvider(self)
        self.metadata_provider = MetadataProvider(self)
        self.opossum_file_content_provider = OpossumFileContentProvider(self)
        self.opossum_output_file_provider = OpossumOutputFileProvider(self)
        self.opossum_file_information = (
            self.file_information_provider.opossum_file_information
        )
        self.opossum_input_metadata = self.metadata_provider.opossum_input_metadata
        self.opossum_package = self.file_information_provider.opossum_package
        self.external_attributions = (
            self.file_information_provider.external_attributions
        )
        self.attribution_breakpoints = (
            self.file_information_provider.attribution_breakpoints
        )
        self.external_attribution_sources = (
            self.file_information_provider.external_attribution_sources
        )
        self.external_attribution_source = (
            self.file_information_provider.external_attribution_source
        )
        self.output_file = self.opossum_output_file_provider.output_file
        self.outfile_metadata = self.opossum_output_file_provider.outfile_metadata
        self.manual_attributions = self.opossum_output_file_provider.manual_attributions
        self.resources_to_attributions = (
            self.opossum_output_file_provider.resources_to_attributions
        )
        self.resolved_external_attributions = (
            self.opossum_output_file_provider.resolved_external_attributions
        )
        self.opossum_file_content = (
            self.opossum_file_content_provider.opossum_file_content
        )


def setup_opossum_file_faker(faker: Faker) -> OpossumFileFaker:
    faker.add_provider(MetadataProvider)
    faker.add_provider(FileInformationProvider)
    faker.add_provider(OpossumOutputFileProvider)
    faker.add_provider(OpossumFileContentProvider)
    faker = cast(OpossumFileFaker, faker)
    return faker
