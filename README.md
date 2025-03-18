<!--
SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>

SPDX-License-Identifier: Apache-2.0
-->

# opossum-file

[![REUSE status](https://api.reuse.software/badge/git.fsfe.org/reuse/api)](https://api.reuse.software/info/git.fsfe.org/reuse/api)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/opossum-tool/opossum-file)](https://github.com/opossum-tool/opossum-file/releases/latest)
![Lint and test](https://github.com/opossum-tool/opossum-file/actions/workflows/lint_and_run_tests.yml/badge.svg)
![build workflow](https://github.com/opossum-tool/opossum-file/actions/workflows/build-and-e2e-test.yml/badge.svg)

This is a library implementing operations around files readable by [OpossumUI](https://github.com/opossum-tool/OpossumUI/).

# Current State

Supports the conversion from the following file formats to `.opossum`:

- `.opossum` itself
- ScanCode (json)
- OWASP Dependency Scan (json)
- more to come...

# License

[Apache-2.0](LICENSE)

# Getting Started

You find the [latest release here](https://github.com/opossum-tool/opossum-file/releases/latest). We offer prebuilt binaries for Linux, MacOS and Windows.

Alternatively, or to get the cutting-edge version, you can clone the repository and run the code yourself. See [Development](#development) below for installation instructions.

# How to Use

## Command-line usage

The CLI uses subcommands. The main command just displays all available subcommands

```bash
Usage: opossum-file [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  generate  Generate an Opossum file from various other file formats.
```

### generate

```bash
Usage: opossum-file generate [OPTIONS]

  Generate an Opossum file from various other file formats. If multiple files
  are provided, they are merged into a single output file.

  Currently supported input formats:
    - ScanCode (json)
    - Opossum
    - OWASP Dependency Scan (json)

Options:
  --opossum PATH         Specify a path to a .opossum file that you would like
                         to include in the final output. Option can be
                         repeated.
  --scan-code-json PATH  Specify a path to a .json file generated by ScanCode
                         that you would like to include in the final output.
                         Option can be repeated.
  --owasp-json PATH      Specify a path to a .json file generated by OWASP
                         dependency scan that you would like to include in the
                         final output. Option can be repeated.
  -o, --outfile TEXT     The file path to write the generated opossum document
                         to. If appropriate, the extension ".opossum" is
                         appended. If the output file already exists, it is
                         overwritten.  [default: output.opossum]
  --help                 Show this message and exit.
```

# Development

## Setting up the environment

1. Install [uv](https://docs.astral.sh/uv/), if you haven't already.
1. Clone the repository.
1. Run `uv sync` to install dependencies.
1. Run `uv run pre-commit install` to install the pre-commit hooks.

## Execution

To execute the code directly (i.e. without building it), use

```bash
uv run opossum-file [OPTIONS] COMMAND [ARGS]...
```

## Architecture

The architecture of the code is described in [a separate document](docs/architecture.md).

## Code quality tooling

To lint and test your changes, run

```shell
uv run task verify
```

Each PR is required to pass these checks, so it is a good idea to run these commands locally before submitting your PR.

Using

```shell
uv run task verify-fix 
```

allows to autofix as many problems as possible.

For an overview of all tasks run

```shell
uv run task --list
```

**Note:** This project uses [faker](https://faker.readthedocs.io/en/master/) for testing. By default, every test runs with a different seed. To fix the seed, just adapt the line in `faker_setup.py` (without committing).

## Build

To build, run

```bash
uv run python build.py opossum-file
```

This will create a self-contained executable file `dist/opossum-file` (`dist/opossum-file.exe` on Windows).

## Creating a new release

Note: You will need the "maintain" role in order to create a new release.

1. Go to the [GitHub releases page](https://github.com/opossum-tool/opossum-file/releases/new) and use the UI to create a new release.
1. The tag should have the format "opossum-file-$YEAR-$MONTH-$DAY" (in case of an Nth release on the same day "opossum-file-$YEAR-$MONTH-$DAY.N").
1. The title of the release equals the tag.
1. Click the button "Generate release notes" to get the description for the release. Then, remove all the contributions from @renovate which are just dependency upgrades.
1. Click "Publish release". This will trigger the CI/CD pipeline which will build the release for all three OSs and upload the artifacts to the release.
