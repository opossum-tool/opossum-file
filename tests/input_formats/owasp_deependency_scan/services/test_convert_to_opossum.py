# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
from opossum_lib.core.entities.metadata import Metadata
from opossum_lib.core.entities.opossum import Opossum
from opossum_lib.input_formats.owasp_deependency_scan.entities.owasp_dependency_report_model import (  # noqa: E501
    ProjectInfoModel,
)
from opossum_lib.input_formats.owasp_deependency_scan.services.convert_to_opossum import (  # noqa: E501
    convert_to_opossum,
)
from tests.setup.owasp_dependency_scan_faker_setup import OwaspFaker


class TestConvertMetadata:
    def test_convert_metadata(self, owasp_faker: OwaspFaker) -> None:
        owasp_model = owasp_faker.owasp_dependency_report_model()
        owasp_project_info: ProjectInfoModel = owasp_model.project_info

        opossum: Opossum = convert_to_opossum(owasp_model)

        metadata: Metadata = opossum.scan_results.metadata

        assert metadata is not None
        assert metadata.project_title == owasp_project_info.name
        assert metadata.file_creation_date == owasp_project_info.report_date
        assert metadata.project_id is not None

    def test_convert_metadata_existing_id_is_copied(
        self, owasp_faker: OwaspFaker
    ) -> None:
        owasp_model = owasp_faker.owasp_dependency_report_model(
            project_info=owasp_faker.project_info_model(artifact_i_d="Some Id")
        )

        opossum: Opossum = convert_to_opossum(owasp_model)

        assert (
            opossum.scan_results.metadata.project_id
            == owasp_model.project_info.artifact_i_d
        )


def test_no_outfile_created(owasp_faker: OwaspFaker) -> None:
    owasp_model = owasp_faker.owasp_dependency_report_model()

    opossum: Opossum = convert_to_opossum(owasp_model)

    assert opossum.review_results is None
