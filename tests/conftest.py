# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

from datetime import datetime

import pytest
from faker.proxy import Faker

from tests.setup.opossum_faker_setup import OpossumFaker, setup_opossum_faker
from tests.setup.opossum_file_faker_setup import (
    OpossumFileFaker,
    setup_opossum_file_faker,
)
from tests.setup.scancode_faker_setup import ScanCodeFaker, setup_scancode_faker


@pytest.fixture
def opossum_file_faker(faker: Faker) -> OpossumFileFaker:
    return setup_opossum_file_faker(faker)


@pytest.fixture
def scancode_faker(faker: Faker) -> ScanCodeFaker:
    return setup_scancode_faker(faker)


@pytest.fixture
def opossum_faker(faker: Faker) -> OpossumFaker:
    return setup_opossum_faker(faker)


@pytest.fixture(autouse=True)
def faker_seed() -> int:
    seed = int(datetime.now().timestamp())
    print("\nSeeding faker with ", seed)
    return seed
