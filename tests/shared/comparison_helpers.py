# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

from typing import Any


def _assert_equal_or_both_falsy(a: Any, b: Any) -> None:
    assert ((not a) and (not b)) or a == b
