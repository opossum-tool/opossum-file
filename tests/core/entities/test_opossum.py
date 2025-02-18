# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
import json
from copy import deepcopy
from pathlib import PurePath

import pytest

from opossum_lib.core.entities.root_resource import RootResource
from opossum_lib.input_formats.opossum.services.convert_to_opossum import (
    convert_to_opossum,
)
from tests.setup.opossum_faker_setup import OpossumFaker


class TestOpossumToOpossumModelConversion:
    def test_moves_outfile(self, opossum_faker: OpossumFaker) -> None:
        opossum = opossum_faker.opossum()

        result = opossum.to_opossum_file_model()

        assert result.output_file == opossum.review_results

    def test_roundtrip_without_preset_attribution_ids(
        self, opossum_faker: OpossumFaker
    ) -> None:
        opossum = opossum_faker.opossum(
            scan_results=opossum_faker.scan_results(attribution_to_id={})
        )
        expected_result = deepcopy(opossum)

        opossum_file = opossum.to_opossum_file_model()

        result = convert_to_opossum(opossum_file)

        # this workaround is necessary as model_dump fails
        result_json = result.model_dump_json()
        expected_result_json = expected_result.model_dump_json()
        result_dict = json.loads(result_json)
        expected_result_dict = json.loads(expected_result_json)
        # this can change due to the generation of new ids
        expected_result_dict["scan_results"]["attribution_to_id"] = None
        result_dict["scan_results"]["attribution_to_id"] = None

        # sort the lists again for comparability
        expected_result_dict["scan_results"]["unassigned_attributions"] = sorted(
            expected_result_dict["scan_results"]["unassigned_attributions"],
            key=lambda x: x["source"]["name"],
        )
        result_dict["scan_results"]["unassigned_attributions"] = sorted(
            result_dict["scan_results"]["unassigned_attributions"],
            key=lambda x: x["source"]["name"],
        )

        assert result_dict == expected_result_dict

    def test_roundtrip_with_preset_attribution_ids(
        self, opossum_faker: OpossumFaker
    ) -> None:
        opossum = opossum_faker.opossum(scan_results=opossum_faker.scan_results())
        expected_result = deepcopy(opossum)

        opossum_file = opossum.to_opossum_file_model()

        result = convert_to_opossum(opossum_file)

        assert result == expected_result

    @pytest.mark.parametrize(
        "path",
        ["/some/absolute/path", "some/relative/path"],
    )
    def test_resource_tree_does_not_start_with_slash(
        self, opossum_faker: OpossumFaker, path: str
    ) -> None:
        resource = RootResource()
        resource.add_resource(opossum_faker.resource(path=PurePath(path)))

        opossum = opossum_faker.opossum(
            scan_results=opossum_faker.scan_results(resources=resource)
        )

        opossum_model = opossum.to_opossum_file_model()
        resulting_resources = opossum_model.input_file.resources

        assert type(resulting_resources) is dict
        assert len(resulting_resources) == 1
        start_path = list(resulting_resources.keys())[0]
        assert start_path == "some"
