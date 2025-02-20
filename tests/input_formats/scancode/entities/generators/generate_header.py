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
    HeaderModel,
    OptionsModel,
    SystemEnvironmentModel,
)
from tests.shared.generator_helpers import random_bool

type TempPathTree = dict[str, TempPathTree | None]


class ScanCodeHeaderProvider(BaseProvider):
    file_provider: FileProvider
    lorem_provider: LoremProvider
    date_provider: DateProvider
    misc_provider: MiscProvider
    internet_provider: InternetProvider
    company_provider: CompanyProvider

    def __init__(self, generator: Any):
        super().__init__(generator)
        self.file_provider = FileProvider(generator)
        self.lorem_provider = LoremProvider(generator)
        self.date_provider = DateProvider(generator)
        self.misc_provider = MiscProvider(generator)
        self.internet_provider = InternetProvider(generator)
        self.company_provider = CompanyProvider(generator)

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
