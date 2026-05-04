# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import PurePath
from typing import Any

from faker.providers import BaseProvider
from faker.providers.date_time import Provider as DateProvider
from faker.providers.file import Provider as FileProvider
from faker.providers.misc import Provider as MiscProvider

from opossum_lib.input_formats.scancode.entities.scancode_model import (
    HeaderModel,
    OptionsModel,
)
from tests.shared.generator_helpers import random_bool

type TempPathTree = dict[str, TempPathTree | None]


class ScanCodeHeaderProvider(BaseProvider):
    file_provider: FileProvider
    date_provider: DateProvider
    misc_provider: MiscProvider

    def __init__(self, generator: Any):
        super().__init__(generator)
        self.file_provider = FileProvider(generator)
        self.date_provider = DateProvider(generator)
        self.misc_provider = MiscProvider(generator)

    def header(
        self,
        *,
        end_timestamp: str | None = None,
        options: OptionsModel | None = None,
    ) -> HeaderModel:
        return HeaderModel(
            end_timestamp=end_timestamp or self.date_provider.iso8601(),
            options=options or self.options(),
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
