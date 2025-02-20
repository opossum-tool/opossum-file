# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any

from faker.providers import BaseProvider
from faker.providers.company import Provider as CompanyProvider
from faker.providers.date_time import Provider as DateProvider
from faker.providers.file import Provider as FileProvider
from faker.providers.internet import Provider as InternetProvider
from faker.providers.lorem.en_US import Provider as LoremProvider
from faker.providers.misc import Provider as MiscProvider

from opossum_lib.input_formats.scancode.entities.scancode_model import (
    FileModel,
    HeaderModel,
    LicenseReferenceModel,
    OptionsModel,
    ScancodeModel,
)
from tests.input_formats.scancode.entities.generators.generate_files import (
    ScanCodeFileProvider,
)
from tests.input_formats.scancode.entities.generators.generate_header import (
    ScanCodeHeaderProvider,
)
from tests.input_formats.scancode.entities.generators.generate_license_references import (  # noqa: E501
    LicenseReferenceProvider,
)

type TempPathTree = dict[str, TempPathTree | None]


class ScanCodeDataProvider(BaseProvider):
    file_provider: FileProvider
    lorem_provider: LoremProvider
    date_provider: DateProvider
    misc_provider: MiscProvider
    internet_provider: InternetProvider
    company_provider: CompanyProvider
    scancode_file_provider: ScanCodeFileProvider
    scancode_header_provider: ScanCodeHeaderProvider
    license_reference_provider: LicenseReferenceProvider

    def __init__(self, generator: Any):
        super().__init__(generator)
        self.file_provider = FileProvider(generator)
        self.lorem_provider = LoremProvider(generator)
        self.date_provider = DateProvider(generator)
        self.misc_provider = MiscProvider(generator)
        self.internet_provider = InternetProvider(generator)
        self.company_provider = CompanyProvider(generator)
        self.scancode_file_provider = ScanCodeFileProvider(generator)
        self.scancode_header_provider = ScanCodeHeaderProvider(generator)
        self.license_reference_provider = LicenseReferenceProvider(generator)

    def scancode_data(
        self,
        *,
        files: list[FileModel] | None = None,
        headers: list[HeaderModel] | None = None,
        options: OptionsModel | None = None,
        license_references: list[LicenseReferenceModel] | None = None,
    ) -> ScancodeModel:
        if headers is None:
            headers = [self.scancode_header_provider.header(options=options)]
        if options is None:
            options = (
                headers[0].options
                if len(headers) == 1
                else self.scancode_header_provider.options()
            )
        if files is None:
            files = self.scancode_file_provider.files(options=options)
        if license_references is None and options.license_references:
            license_references = self.license_reference_provider.license_references(
                files=files
            )
        return ScancodeModel(
            files=files, headers=headers, license_references=license_references
        )
