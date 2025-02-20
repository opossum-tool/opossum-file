# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import PurePath
from typing import Any

from faker.providers import BaseProvider
from faker.providers.company import Provider as CompanyProvider
from faker.providers.date_time import Provider as DateProvider
from faker.providers.file import Provider as FileProvider
from faker.providers.internet import Provider as InternetProvider
from faker.providers.lorem.en_US import Provider as LoremProvider
from faker.providers.misc import Provider as MiscProvider

from opossum_lib.input_formats.scancode.entities.scancode_model import (
    ExtraDataModel,
    FileModel,
    HeaderModel,
    LicenseReferenceModel,
    OptionsModel,
    ScancodeModel,
    SystemEnvironmentModel,
)
from tests.input_formats.scancode.entities.generators.generate_files import (
    ScanCodeFileProvider,
)
from tests.shared.generator_helpers import entry_or_none, random_bool, random_list

type TempPathTree = dict[str, TempPathTree | None]


class ScanCodeDataProvider(BaseProvider):
    file_provider: FileProvider
    lorem_provider: LoremProvider
    date_provider: DateProvider
    misc_provider: MiscProvider
    internet_provider: InternetProvider
    company_provider: CompanyProvider
    scancode_file_provider: ScanCodeFileProvider

    def __init__(self, generator: Any):
        super().__init__(generator)
        self.file_provider = FileProvider(generator)
        self.lorem_provider = LoremProvider(generator)
        self.date_provider = DateProvider(generator)
        self.misc_provider = MiscProvider(generator)
        self.internet_provider = InternetProvider(generator)
        self.company_provider = CompanyProvider(generator)
        self.scancode_file_provider = ScanCodeFileProvider(generator)

    def scancode_data(
        self,
        *,
        files: list[FileModel] | None = None,
        headers: list[HeaderModel] | None = None,
        options: OptionsModel | None = None,
        license_references: list[LicenseReferenceModel] | None = None,
    ) -> ScancodeModel:
        if headers is None:
            headers = [self.header(options=options)]
        if options is None:
            options = headers[0].options if len(headers) == 1 else self.options()
        if files is None:
            files = self.scancode_file_provider.files(options=options)
        if license_references is None and options.license_references:
            license_references = self.license_references(files=files)
        return ScancodeModel(
            files=files, headers=headers, license_references=license_references
        )

    def header(
        self,
        *,
        duration: float | None = None,
        end_timestamp: str | None = None,
        errors: list | None = None,
        extra_data: ExtraDataModel | None = None,
        message: Any | None = None,
        notice: str | None = None,
        options: OptionsModel | None = None,
        output_format_version: str | None = None,
        start_timestamp: str | None = None,
        tool_name: str | None = None,
        tool_version: str | None = None,
        warnings: list | None = None,
    ) -> HeaderModel:
        return HeaderModel(
            duration=duration or self.random_int(max=9999999) / 1e3,
            end_timestamp=end_timestamp or self.date_provider.iso8601(),
            errors=errors or [],
            extra_data=extra_data or self.extra_data(),
            message=message,
            notice=notice or "Generated with ScanCode and provided...",
            options=options or self.options(),
            output_format_version=output_format_version or "4.0.0",
            start_timestamp=start_timestamp or self.date_provider.iso8601(),
            tool_name=tool_name or "scancode-toolkit",
            tool_version=tool_version or "v32.3.0-20-g93ca65c34e",
            warnings=warnings or [],
        )

    def options(
        self,
        *,
        input: list[str] | None = None,
        strip_root: bool | None = None,
        full_root: bool | None = None,
        copyright: bool | None = None,
        license: bool | None = None,
        package: bool | None = None,
        email: bool | None = None,
        url: bool | None = None,
        info: bool | None = None,
        license_references: bool | None = None,
        **additional_options: dict[str, Any],
    ) -> OptionsModel:
        if strip_root is None and full_root is None:
            strip_root, full_root = self.random_element(
                [(False, False), (True, False), (False, True)]
            )
        strip_root = random_bool(self.misc_provider, strip_root)
        copyright = random_bool(self.misc_provider, copyright)
        package = random_bool(self.misc_provider, package)
        email = random_bool(self.misc_provider, email)
        url = random_bool(self.misc_provider, url)
        info = random_bool(self.misc_provider, info)
        if strip_root is None:
            strip_root = (not full_root) and self.misc_provider.boolean()
        if full_root is None:
            full_root = (not strip_root) and self.misc_provider.boolean()
        if license is None:
            license = license_references or self.misc_provider.boolean()
        if license_references is None:
            license_references = license and self.misc_provider.boolean()
        if input is None:
            absolute_path = self.misc_provider.boolean()
            input = [
                self.file_provider.file_path(
                    depth=self.random_int(min=1, max=5),
                    absolute=absolute_path,
                    extension="",
                )
            ]

            if not absolute_path and self.misc_provider.boolean():
                second_path = self.file_provider.file_path(
                    depth=self.random_int(min=1, max=5),
                    absolute=False,
                    extension="",
                )
                first_path_segments = PurePath(input[0]).parts
                basepath = PurePath(
                    *first_path_segments[
                        0 : self.random_int(1, max=len(first_path_segments))
                    ]
                )
                input.append(str(basepath / second_path))

        return OptionsModel(
            input=input,
            strip_root=strip_root,
            full_root=full_root,
            copyright=copyright,
            license=license,
            package=package,
            email=email,
            url=url,
            info=info,
            license_references=license_references,
            **additional_options,
        )

    def extra_data(
        self,
        *,
        files_count: int | None = None,
        spdx_license_list_version: str | None = None,
        system_environment: SystemEnvironmentModel | None = None,
    ) -> ExtraDataModel:
        return ExtraDataModel(
            files_count=files_count or self.random_int(),
            spdx_license_list_version=spdx_license_list_version
            or self.numerify("#.##"),
            system_environment=system_environment or self.system_environment(),
        )

    def system_environment(
        self,
        *,
        cpu_architecture: str | None = None,
        operating_system: str | None = None,
        platform: str | None = None,
        platform_version: str | None = None,
        python_version: str | None = None,
    ) -> SystemEnvironmentModel:
        operating_system = operating_system or self.random_element(
            ["linux", "windows", "macos"]
        )
        return SystemEnvironmentModel(
            cpu_architecture=cpu_architecture or self.random_element(["32", "64"]),
            operating_system=operating_system,
            platform=platform
            or operating_system + self.numerify("-##.###.####-generic"),
            platform_version=platform_version or "#" + self.numerify("###"),
            python_version=python_version or self.numerify("#.##.###"),
        )

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
