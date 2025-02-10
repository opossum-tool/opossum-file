# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

from collections.abc import Sequence
from typing import Any, cast

from faker import Faker, Generator

from tests.input_formats.scancode.entities.generators.generate_scancode_file import (
    ScanCodeDataProvider,
)


class ScanCodeFaker(Faker):
    scancode_data_provider: ScanCodeDataProvider
    # metadata_provider: MetadataProvider
    # opossum_output_file_provider: OpossumOutputFileProvider
    # opossum_file_content_provider: OpossumFileContentProvider

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
        scdp = ScanCodeDataProvider(generator)
        self.scancode_data_provider = scdp
        self.generate_path_structure = scdp.generate_path_structure
        self.files = scdp.files
        self.sc_email = scdp.email
        self.sc_url = scdp.url
        self.license_detection = scdp.license_detection
        self.match = scdp.match
        self.single_file = scdp.single_file
        self.single_folder = scdp.single_folder
        self.scancode_data = scdp.scancode_data
        self.header = scdp.header
        self.options = scdp.options
        self.extra_data = scdp.extra_data
        self.system_environment = scdp.system_environment
        self.global_license_detections = scdp.global_license_detections
        self.copyright = scdp.copyright


def setup_scancode_faker(faker: Faker) -> ScanCodeFaker:
    faker.add_provider(ScanCodeDataProvider)
    faker = cast(ScanCodeFaker, faker)
    return faker
