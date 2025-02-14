#  SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#  #
#  SPDX-License-Identifier: Apache-2.0
#
# SPDX-License-Identifier: Apache-2.0


from opossum_lib.input_formats.scancode.constants import SCANCODE_SOURCE_NAME
from opossum_lib.input_formats.scancode.services.convert_to_opossum import (
    convert_to_opossum,
)
from opossum_lib.shared.entities.opossum_input_file_model import (
    OpossumPackageModel,
    SourceInfoModel,
)
from tests.setup.scancode_faker_setup import ScanCodeFaker


class TestGetAttributionInfo:
    def test_get_attribution_info_directory(
        self, scancode_faker: ScanCodeFaker
    ) -> None:
        folder = scancode_faker.single_folder(path="some/single/folder")
        scancode_data = scancode_faker.scancode_data(files=[folder])
        opossum = convert_to_opossum(scancode_data)
        assert len(opossum.scan_results.resources.children) == 1
        assert (
            list(opossum.scan_results.resources.children.values())[0].attributions == []
        )

    def test_get_attribution_info_from_file_without_detections(
        self,
        scancode_faker: ScanCodeFaker,
    ) -> None:
        file = scancode_faker.single_file(
            path="some/single/file", license_detections=[]
        )
        scancode_data = scancode_faker.scancode_data(files=[file])
        opossum = convert_to_opossum(scancode_data)
        assert len(opossum.scan_results.resources.children) == 1
        assert (
            list(opossum.scan_results.resources.children.values())[0].attributions == []
        )

    def test_get_attribution_info_file_multiple(
        self, scancode_faker: ScanCodeFaker
    ) -> None:
        match1 = scancode_faker.match(
            license_expression_spdx="Apache-2.0",
            from_file="A",
            score=75,
            rule_relevance=50,
        )
        match2 = scancode_faker.match(
            license_expression_spdx="Apache-2.0",
            from_file="A",
            score=95,
            rule_relevance=50,
        )
        match3 = scancode_faker.match(
            license_expression_spdx="MIT",
            from_file="A",
            score=50,
            rule_relevance=50,
        )
        license1 = scancode_faker.license_detection(
            license_expression_spdx="Apache-2.0",
            matches=[match1, match2],
        )
        license2 = scancode_faker.license_detection(
            license_expression_spdx="MIT",
            matches=[match3],
        )
        copyright1 = scancode_faker.copyright(copyright="Me")
        copyright2 = scancode_faker.copyright(copyright="Myself")
        copyright3 = scancode_faker.copyright(copyright="I")
        file = scancode_faker.single_file(
            path="A",
            license_detections=[license1, license2],
            copyrights=[copyright1, copyright2, copyright3],
        )
        scancode_data = scancode_faker.scancode_data(files=[file])
        opossum = convert_to_opossum(scancode_data)
        attributions = (
            opossum.to_opossum_file_model().input_file.external_attributions.values()
        )

        expected1 = OpossumPackageModel(
            source=SourceInfoModel(name=SCANCODE_SOURCE_NAME, document_confidence=50),
            license_name="MIT",
            copyright="Me\nMyself\nI",
            attribution_confidence=50,
        )
        expected2 = OpossumPackageModel(
            source=SourceInfoModel(name=SCANCODE_SOURCE_NAME, document_confidence=95),
            license_name="Apache-2.0",
            copyright="Me\nMyself\nI",
            attribution_confidence=95,
        )
        assert len(attributions) == 2
        attribution1, attribution2 = sorted(
            attributions, key=lambda attr: attr.attribution_confidence or 0
        )
        assert attribution1.source == expected1.source
        assert attribution1.license_name == expected1.license_name
        assert attribution1.copyright == expected1.copyright
        assert attribution1.attribution_confidence == expected1.attribution_confidence

        assert attribution2.source == expected2.source
        assert attribution2.license_name == expected2.license_name
        assert attribution2.copyright == expected2.copyright
        assert attribution2.attribution_confidence == expected2.attribution_confidence
