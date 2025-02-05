# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
from typing import Any

from faker.providers import BaseProvider

from opossum_lib.core.entities.opossum import Opossum
from opossum_lib.core.entities.scan_results import ScanResults
from opossum_lib.shared.entities.opossum_output_file_model import OpossumOutputFileModel
from tests.core.entities.generators.scan_results_provider import ScanResultsProvider
from tests.input_formats.opossum.entities.generators.generate_outfile_information import (  # noqa
    OpossumOutputFileProvider,
)


class OpossumProvider(BaseProvider):
    review_result_provider: OpossumOutputFileProvider
    scan_results_provider: ScanResultsProvider

    def __init__(self, generator: Any):
        super().__init__(generator)
        self.review_result_provider = OpossumOutputFileProvider(generator)
        self.scan_results_provider = ScanResultsProvider(generator)

    def opossum(
        self,
        scan_results: ScanResults | None = None,
        review_results: OpossumOutputFileModel | None = None,
        generate_review_results: bool | None = None,
    ) -> Opossum:
        if generate_review_results is None:
            generate_review_results = bool(self.random_int(max=1))
        return Opossum(
            scan_results=scan_results
            or self.scan_results_provider.scan_results(attribution_to_id={}),
            review_results=review_results
            or (generate_review_results and self.review_result_provider.output_file())
            or None,
        )
