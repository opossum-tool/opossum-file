<!--
SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>

SPDX-License-Identifier: Apache-2.0
-->

# Architecture of `opossum-file`

The `opossum-file` package is composed of three primary components:

1. [**Input format readers**](#input-format-readers): responsible for reading and converting different input file formats into the internal `Opossum` representation.
1. [**Internal representation**](#internal-representation-of-opossum-files): a data structure used for all operations on `opossum` files, such as merging, which provides an easier-to-work-with format than the on-disk representation.
1. [**On-disk representation**](#on-disk-opossum-format): the format used to save `opossum` files to disk, defined using `pydantic`.

![Architecture diagram](opossum-file-architecture.png)

The following sections provide a detailed overview of each component.

## Input format readers

`opossum-file` supports multiple input file formats, which are converted into the internal `Opossum` representation before further processing. This conversion is facilitated by the `InputReader` interface, which consists of a single method `read() -> Opossum`. The file path is set via the constructor, a complete invocation example is `ScancodeFileReader(path).read()`.

### Adding a New Input File Reader

To add support for a new input file format, follow these steps:

1. Create a new subfolder in `src/opossum_lib/input_formats/<format_name>`.
1. Define the schema using `pydantic` (if applicable) in `<format_name>/entities`.
1. Implement the conversion from the new schema to `Opossum` in `<format_name>/services/convert_to_opossum.py`.
1. Write tests for the new format, mirroring the folder structure in `tests`.
1. Create a subclass of `InputReader` with a `pathlib.Path` constructor and an instance method `.read()` returning an `Opossum` instance.
1. Integrate the new reader with the CLI by adding a new argument in `src/opossum_lib/cli.py`, using existing arguments as a blueprint.

## Internal Representation of Opossum Files

All operations on `opossum` files, such as merging, are performed using an internal representation of the data. This representation differs from the on-disk format in two key aspects:

- The `resourcesToAttribution` join map is resolved by inlining attributions from `externalAttributions` into the corresponding resources.
- The folder structure defined by `resources` is reflected by resources directly containing their child resources.

This data structure ensures consistency between `resources`, `resourcesToAttribution`, and `externalAttributions` without requiring updates to multiple locations.

## On-Disk Opossum Format

The on-disk format of `opossum` files is defined using [`pydantic`](https://docs.pydantic.dev/latest/) in [`opossum_file_model.py`](../src/opossum_lib/shared/entities/opossum_file_model.py). The conversion between the internal `Opossum` and `OpossumFileModel` is implemented in [`convert_to_opossum.py`](src/opossum_lib/input_formats/opossum/services/convert_to_opossum.py), following the same structure as other input file formats. To write an instance of `OpossumFileModel` to file, use the `write_opossum_file` function from [`write_opossum_file.py`](../src/opossum_lib/core/services/write_opossum_file.py).
