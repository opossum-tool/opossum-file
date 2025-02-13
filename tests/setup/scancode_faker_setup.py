# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

from typing import cast

from faker import Faker

from tests.input_formats.scancode.entities.generators.generate_scancode_file import (
    ScanCodeDataProvider,
)


## This class serves as a stub to enable tab-completion in the tests and satisfy mypy
class ScanCodeFaker(Faker):
    def __init__(self) -> None:
        scdp = ScanCodeDataProvider(self)
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
    return cast(ScanCodeFaker, faker)
