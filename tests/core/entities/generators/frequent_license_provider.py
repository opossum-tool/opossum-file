# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
from typing import Any

from faker.providers import BaseProvider
from faker.providers.lorem.en_US import Provider as LoremProvider

from opossum_lib.core.entities.frequent_license import FrequentLicense


class FrequentLicenseProvider(BaseProvider):
    lorem_provider: LoremProvider

    def __init__(self, generator: Any) -> None:
        super().__init__(generator)
        self.lorem_provider = LoremProvider(generator)

    def frequent_license(
        self,
        full_name: str | None = None,
        short_name: str | None = None,
        default_text: str | None = None,
    ) -> FrequentLicense:
        return FrequentLicense(
            full_name=full_name or self.lorem_provider.sentence(),
            short_name=short_name or self.lexify("### License"),
            default_text=default_text or self.lorem_provider.text(),
        )
