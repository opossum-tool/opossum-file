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
from tests.shared.generator_helpers import entry_or_none, random_bool, random_list

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
                file.detected_license_expression_spdx
                for file in files
                if file.detected_license_expression_spdx
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
            key=key or self.lorem_provider.word() + self.numerify("-#.#"),
            language=language or self.misc_provider.language_code(),
            short_name=short_name or short_name,
            name=name or self.lorem_provider.word() + self.numerify(" #.# license"),
            category=category
            or self.random_element(
                [
                    "Proprietary Free",
                    "Permissive",
                    "Copyleft Limited",
                    "Public Domain",
                    "Copyleft",
                ]
            ),
            owner=owner or " ".join(self.lorem_provider.words()),
            homepage_url=homepage_url or self.internet_provider.url(),
            notes=notes
            or entry_or_none(self.misc_provider, self.lorem_provider.sentence()),
            is_builtin=random_bool(self.misc_provider, is_builtin),
            is_exception=random_bool(self.misc_provider, is_exception),
            is_unknown=random_bool(self.misc_provider, is_unknown),
            is_generic=random_bool(self.misc_provider, is_generic),
            spdx_license_key=spdx_license_key or self._license_key(),
            other_spdx_license_keys=other_spdx_license_keys
            or entry_or_none(self.misc_provider, random_list(self, self._license_key)),
            osi_license_key=osi_license_key
            or entry_or_none(self.misc_provider, self._license_key()),
            text_urls=text_urls
            or entry_or_none(self.misc_provider, [self.internet_provider.url()]),
            osi_url=osi_url
            or entry_or_none(self.misc_provider, self.internet_provider.url()),
            faq_url=faq_url
            or entry_or_none(self.misc_provider, self.internet_provider.url()),
            other_urls=other_urls
            or entry_or_none(
                self.misc_provider, random_list(self, self.internet_provider.url)
            ),
            key_aliases=key_aliases or entry_or_none(self.misc_provider, []),
            minimum_coverage=minimum_coverage or self.random_int(max=100),
            standard_notice=standard_notice
            or entry_or_none(self.misc_provider, self.lorem_provider.sentence()),
            ignorable_copyrights=ignorable_copyrights
            or entry_or_none(self.misc_provider, []),
            ignorable_holders=ignorable_holders
            or entry_or_none(self.misc_provider, []),
            ignorable_authors=ignorable_authors
            or entry_or_none(self.misc_provider, []),
            ignorable_urls=ignorable_urls or entry_or_none(self.misc_provider, []),
            ignorable_emails=ignorable_emails or entry_or_none(self.misc_provider, []),
            text=text or self.lorem_provider.paragraph(),
            scancode_url=scancode_url
            or entry_or_none(self.misc_provider, self.internet_provider.url()),
            licensedb_url=licensedb_url
            or entry_or_none(self.misc_provider, self.internet_provider.url()),
            spdx_url=spdx_url
            or entry_or_none(self.misc_provider, self.internet_provider.url()),
        )

    def _license_key(self) -> str:
        return "-".join(self.lorem_provider.words(nb=5))
