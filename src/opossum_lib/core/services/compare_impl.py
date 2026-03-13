# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
import logging

from deepdiff import DeepDiff

from opossum_lib.core.entities.metadata import Metadata
from opossum_lib.core.entities.opossum import Opossum
from opossum_lib.core.entities.scan_results import ScanResults
from opossum_lib.shared.entities.opossum_output_file_model import OpossumOutputFileModel


def compare_impl(first: Opossum, second: Opossum) -> None:
    logging.info(f"Comparing {first} with {second}")

    _compare_scan_results(first.scan_results, second.scan_results)
    _compare_review_results(first.review_results, second.review_results)


def _compare_scan_results(first: ScanResults, second: ScanResults) -> None:
    _compare_metadata(first.metadata, second.metadata)


def _compare_metadata(first: Metadata, second: Metadata) -> None:
    diff_result = DeepDiff(first, second)
    if diff_result != {}:
        logging.error(f"Different metadata: {diff_result}")
    else:
        logging.info("Metadata is identical")


def _compare_review_results(
    first: OpossumOutputFileModel | None, second: OpossumOutputFileModel | None
) -> None:
    if first is None and second is None:
        logging.info("Both files do not contain review results")
    elif first is not None and second is not None:
        logging.info(
            "Both files contain review results,"
            " no further comparison implemented at this point"
        )
    elif first is None and second is not None:
        logging.error("Only the first file contains review results")
    else:
        logging.error("Only the second file contains review results")
