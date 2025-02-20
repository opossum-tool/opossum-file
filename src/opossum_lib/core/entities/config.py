#  SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#  #
#  SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from opossum_lib.shared.entities.opossum_input_file_model import ConfigModel


class Config(BaseModel):
    model_config = ConfigDict(frozen=True, extra="allow")
    classifications: dict[int, str] = {}

    def to_opossum_file_model(self) -> ConfigModel:
        extra = self.model_extra or {}
        classifications = self.classifications or None
        return ConfigModel(classifications=classifications, **extra)
