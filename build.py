# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

import sys

import PyInstaller.__main__


def main() -> None:
    executable_name = sys.argv[1]
    one_file_or_dir = sys.argv[2]
    if one_file_or_dir != "--onefile" and one_file_or_dir != "--onedir":
        # We default to --onefile mode for backwards compatability
        one_file_or_dir = "--onefile"
    PyInstaller.__main__.run(
        [
            one_file_or_dir,
            "--name",
            f"{executable_name}",
            "src/opossum_lib/cli.py",
        ]
    )


if __name__ == "__main__":
    main()
