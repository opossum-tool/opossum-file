# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any

from faker.providers import BaseProvider
from faker.providers.internet import Provider as InternetProvider
from faker.providers.lorem.en_US import Provider as LoremProvider
from faker.providers.misc import Provider as MiscProvider

from opossum_lib.input_formats.scancode.entities.scancode_model import (
    FileModel,
    LicenseReferenceModel,
)
from tests.shared.generator_helpers import random_list

type TempPathTree = dict[str, TempPathTree | None]


class LicenseReferenceProvider(BaseProvider):
    lorem_provider: LoremProvider
    misc_provider: MiscProvider
    internet_provider: InternetProvider

    def __init__(self, generator: Any):
        super().__init__(generator)
        self.lorem_provider = LoremProvider(generator)
        self.misc_provider = MiscProvider(generator)
        self.internet_provider = InternetProvider(generator)

    def license_references(
        self, files: list[FileModel] | None = None
    ) -> list[LicenseReferenceModel]:
        license_expressions = random_list(
            self, self._license_key, min_number_of_entries=2, max_number_of_entries=3
        )
        if files:
            additional_license_expressions = [
                detection.license_expression_spdx
                for file in files
                for detection in file.license_detections or []
            ]
            license_expressions += additional_license_expressions
        return [
            self.license_reference(
                spdx_license_key=self.random_element(license_expressions)
            )
            for _ in range(self.random_int(max=5))
        ]

    def license_reference(
        self,
        key: str | None = None,
        language: str | None = None,
        short_name: str | None = None,
        name: str | None = None,
        category: str | None = None,
        owner: str | None = None,
        homepage_url: str | None | None = None,
        notes: str | None = None,
        is_builtin: bool = False,
        is_exception: bool = False,
        is_unknown: bool = False,
        is_generic: bool = False,
        spdx_license_key: str | None = None,
        other_spdx_license_keys: list[str] | None = None,
        osi_license_key: str | None = None,
        text_urls: list[str] | None = None,
        osi_url: str | None = None,
        faq_url: str | None = None,
        other_urls: list[str] | None = None,
        key_aliases: list[str] | None = None,
        minimum_coverage: int | None = None,
        standard_notice: str | None = None,
        ignorable_copyrights: list[str] | None = None,
        ignorable_holders: list[str] | None = None,
        ignorable_authors: list[str] | None = None,
        ignorable_urls: list[str] | None = None,
        ignorable_emails: list[str] | None = None,
        text: str | None = None,
        scancode_url: str | None = None,
        licensedb_url: str | None = None,
        spdx_url: str | None = None,
    ) -> LicenseReferenceModel:
        return LicenseReferenceModel(
            spdx_license_key=spdx_license_key or self._license_key(),
            text=text or self.lorem_provider.paragraph(),
        )

    def _license_key(self) -> str:
        return "-".join(self.lorem_provider.words(nb=5))
