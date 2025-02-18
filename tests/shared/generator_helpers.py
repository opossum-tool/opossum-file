# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
from collections.abc import Callable
from typing import TypeVar

from faker.providers import BaseProvider
from faker.providers.misc import Provider as MiscProvider


def entry_or_none[T](
    faker: MiscProvider, entry: T, chance_of_getting_entry: int = 50
) -> T | None:
    if faker.boolean(chance_of_getting_entry):
        return entry
    else:
        return None


def random_list[T](
    faker: BaseProvider,
    entry_generator: Callable[[], T],
    max_number_of_entries: int = 3,
    min_number_of_entries: int = 1,
) -> list[T]:
    number_of_entries = faker.random_int(min_number_of_entries, max_number_of_entries)
    return [entry_generator() for _ in range(number_of_entries)]


T = TypeVar("T")
Q = TypeVar("Q")


def random_dict(
    faker: BaseProvider,
    key_generator: Callable[[], T],
    entry_generator: Callable[[], Q],
    min_number_of_entries: int = 1,
    max_number_of_entries: int = 10,
) -> dict[T, Q]:
    number_of_entries = faker.random_int(min_number_of_entries, max_number_of_entries)
    return {key_generator(): entry_generator() for _ in range(number_of_entries)}


def random_bool(
    misc_provider: MiscProvider, default: bool | None, chance_of_getting_true: int = 50
) -> bool:
    if default is None:
        return misc_provider.boolean(chance_of_getting_true=chance_of_getting_true)
    else:
        return default
