# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from opossum_lib.shared.entities.camel_base_model import CamelBaseModel

## Adapted to https://github.com/jeremylong/DependencyCheck/
# blob/main/core/src/main/resources/templates/jsonReport.vsl


class OWASPDependencyReportModel(CamelBaseModel):
    report_schema: str
    scan_info: ScanInfoModel
    project_info: ProjectInfoModel
    dependencies: list[DependencyModel]


class ScanInfoModel(CamelBaseModel):
    engine_version: str
    data_source: list[DataSourceModel]
    analysis_exceptions: list[AnalysisExceptionModel] | None = None


class AnalysisExceptionModel(CamelBaseModel):
    exception: ExceptionModel


class ExceptionModel(CamelBaseModel):
    message: str
    stack_trace: list[str] | None = None
    cause: ExceptionModel | None = None


class DataSourceModel(CamelBaseModel):
    name: str
    timestamp: str


class ProjectInfoModel(CamelBaseModel):
    name: str
    report_date: str
    group_i_d: str | None = None
    artifact_i_d: str | None = None
    application_version: str | None = None
    credits: dict[str, str] | None = None


class DependencyModel(CamelBaseModel):
    is_virtual: bool
    file_name: str
    file_path: str
    md5: str | None = None
    sha256: str | None = None
    sha1: str | None = None
    description: str | None = None
    license: str | None = None
    project_references: list[str] | None = None
    included_by: list[IncludedByModel] | None = None
    related_dependencies: list[RelatedDependencyModel] | None = None
    evidence_collected: EvidenceCollectedModel
    packages: list[PackageModel] | None = None
    vulnerability_ids: list[VulnerabilityIdModel] | None = None
    suppressed_vulnerability_ids: list[VulnerabilityIdModel] | None = None
    vulnerabilities: list[VulnerabilityModel] | None = None
    suppressed_vulnerabilities: list[VulnerabilityModel] | None = None


class CvssV2Model(CamelBaseModel):
    score: float
    access_vector: str
    access_complexity: str
    authenticationr: str
    confidentiality_impact: str
    integrity_impact: str
    availability_impact: str
    severity: str
    version: str | None = None
    exploitability_score: str | None = None
    impact_score: str | None = None
    ac_insuf_info: str | None = None
    obtain_all_privilege: str | None = None
    obtain_user_privilege: str | None = None
    obtain_other_privilege: str | None = None
    user_interaction_required: str | None = None


class CvssV3Model(CamelBaseModel):
    base_score: float
    attack_vector: str
    attack_complexity: str
    privileges_required: str
    user_interaction: str
    scope: str
    confidentiality_impact: str
    integrity_impact: str
    availability_impact: str
    base_severity: str
    exploitability_score: str | None = None
    impact_score: str | None = None
    version: str | None = None


class CvssV4Model(CamelBaseModel):
    vector_string: str | None = None
    source: str | None = None
    type: str | None = None
    version: str | None = None
    attack_vector: str | None = None
    attack_complexity: str | None = None
    attack_requirements: str | None = None
    privileges_required: str | None = None
    user_interaction: str | None = None
    vulnerable_system_confidentiality: str | None = None
    vulnerable_system_integrity: str | None = None
    vulnerable_system_availability: str | None = None
    subsequent_system_confidentiality: str | None = None
    subsequent_system_integrity: str | None = None
    subsequent_system_availability: str | None = None
    exploit_maturity: str | None = None
    confidentiality_requirements: str | None = None
    integrity_requirements: str | None = None
    availability_requirements: str | None = None
    modified_attack_vector: str | None = None
    modified_attack_complexity: str | None = None
    modified_attack_requirements: str | None = None
    modified_privileges_required: str | None = None
    modified_user_interaction: str | None = None
    modified_vulnerable_system_confidentiality: str | None = None
    modified_vulnerable_system_integrity: str | None = None
    modified_vulnerable_system_availability: str | None = None
    modified_subsequent_system_confidentiality: str | None = None
    modified_subsequent_system_integrity: str | None = None
    modified_subsequent_system_availability: str | None = None
    safety: str | None = None
    automatable: str | None = None
    recovery: str | None = None
    value_density: str | None = None
    vulnerability_response_effort: str | None = None
    provider_urgency: str | None = None
    base_score: float | None = None
    base_severity: str | None = None
    threat_score: float | None = None
    threat_severity: str | None = None
    environmental_score: float | None = None
    environmental_severity: str | None = None


class VulnerabilityModel(CamelBaseModel):
    source: str
    name: str
    cvssv2: CvssV2Model | None = None
    cvssv3: CvssV3Model | None = None
    cvssv4: CvssV4Model | None = None
    cwes: list[str] | None = None
    description: str | None = None
    notes: str | None = None
    references: list[ReferenceModel] | None = None
    vulnerable_software: list[VulnerableSoftwareModel] | None = None
    unscored: bool | None = None
    severity: str | None = None
    known_exploited_vulnerability: KnownExploitedVulnerabilityModel | None = None


class VulnerableSoftwareModel(CamelBaseModel):
    software: SoftwareModel


class SoftwareModel(CamelBaseModel):
    id: str
    vulnerability_id_matched: bool | None = None
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None
    vulnerable: str | None = None


class ReferenceModel(CamelBaseModel):
    source: str
    url: str | None = None
    name: str | None = None


class KnownExploitedVulnerabilityModel(CamelBaseModel):
    VendorProject: str | None = None
    Product: str | None = None
    Name: str | None = None
    DateAdded: str | None = None
    Description: str | None = None
    RequiredAction: str | None = None
    DueDate: str | None = None
    Notes: str | None = None


class VulnerabilityIdModel(CamelBaseModel):
    id: str
    confidence: str | None = None
    url: str | None = None
    description: str | None = None
    notes: str | None = None


class IncludedByModel(CamelBaseModel):
    reference: str
    type: str | None = None


class RelatedDependencyModel(CamelBaseModel):
    is_virtual: bool
    file_name: str
    file_path: str
    md5: str | None = None
    sha256: str | None = None
    sha1: str | None = None
    package_ids: list[PackageIdModel] | None = None


class PackageIdModel(CamelBaseModel):
    id: str
    url: str | None = None
    notes: str | None = None
    description: str | None = None


class EvidenceCollectedModel(CamelBaseModel):
    product_evidence: list[EvidenceModel]
    version_evidence: list[EvidenceModel]
    vendor_evidence: list[EvidenceModel]


class EvidenceModel(CamelBaseModel):
    type: str
    confidence: str
    source: str
    name: str
    value: str


class PackageModel(CamelBaseModel):
    id: str
    confidence: str | None = None
    url: str | None = None
    description: str | None = None
    notes: str | None = None
