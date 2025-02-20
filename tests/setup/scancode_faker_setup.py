# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

from typing import cast

from faker import Faker

from tests.input_formats.scancode.entities.generators.generate_files import (
    ScanCodeFileProvider,
)
from tests.input_formats.scancode.entities.generators.generate_header import (
    ScanCodeHeaderProvider,
)
from tests.input_formats.scancode.entities.generators.generate_scancode_file import (
    ScanCodeDataProvider,
)


## This class serves as a stub to enable tab-completion in the tests and satisfy mypy
class ScanCodeFaker(Faker):
    def __init__(self) -> None:
        scdp = ScanCodeDataProvider(self)
        self.scancode_data = scdp.scancode_data

        self.license_references = scdp.license_references
        self.license_reference = scdp.license_reference

        schp = ScanCodeHeaderProvider(self)
        self.header = schp.header
        self.options = schp.options
        self.extra_data = schp.extra_data
        self.system_environment = schp.system_environment

        scdf = ScanCodeFileProvider(self)
        self.generate_path_structure = scdf.generate_path_structure
        self.files = scdf.files
        self.single_folder = scdf.single_folder
        self.single_file = scdf.single_file
        self.random_purl = scdf.random_purl
        self.package_data = scdf.package_data
        self.dependency = scdf.dependency
        self.copyright = scdf.copyright
        self.sc_email = scdf.sc_email
        self.sc_url = scdf.sc_url
        self.license_detection = scdf.license_detection
        self.match = scdf.match


def setup_scancode_faker(faker: Faker) -> ScanCodeFaker:
    faker.add_provider(ScanCodeDataProvider)
    faker.add_provider(ScanCodeFileProvider)
    faker.add_provider(ScanCodeHeaderProvider)
    return cast(ScanCodeFaker, faker)
