"""Модуль с моделями данных"""

from fastui import components as c
from pydantic import BaseModel


class ProjectConfigAddDTO(BaseModel):
    name: str | None
    type: str | None
    dir_path: str | None
    description: str | None = None
    scan_config_id: int

class ProjectConfigGetDTO(ProjectConfigAddDTO):
    id: int

class TableProjectConfigGetDTO(BaseModel):
    id: c.Link
    name: str
    type: str
    dir_path: str
    description: str

class ScanConfigAddDTO(BaseModel):
    name: str
    host: str
    user: str
    secret: str
    description: str | None = None
    date: str | None = None
    port: str | None = None

class ProjectScanConfigAddDTO(BaseModel):
    name: str
    type: str
    dir_path: str
    description: str
    scan_config_id: int

class ScanConfigGetDTO(ScanConfigAddDTO):
    id: int
    projects: list[ProjectConfigGetDTO]

class TableScanConfigDTO(BaseModel):
    id: c.Link
    name: str
    host: str
    user: str
    date: str

class AffectedDTO(BaseModel):
    name: str
    vendor: str
    type: str

    start_condition: str
    start_value: str
    end_value: str
    end_condition: str

class AffectedGetDTO(AffectedDTO):
    id: int

class AffectedProjectDTO(BaseModel):
    affected_id: int
    project_config_id: int

class RatingGetDTO(BaseModel):
    id: int
    method: str
    score: float
    severity: str
    source_name: str
    source_url: str
    vector: str
    version: float

class TableRatingDTO(BaseModel):
    score: float
    severity: str
    vector: str
    source_name: str
    source_url: c.Link

class ReferenceGetDTO(BaseModel):
    id: int
    source: str
    url: str

class VulnerGetDTO(BaseModel):
    global_identifier: str
    identifier: str | None
    description: str | None
    source_name: str | None
    source_url: str | None = None

    affected: list[AffectedGetDTO] | None = None
    ratings: list[RatingGetDTO] | None = None
    references: list[ReferenceGetDTO] | None = None

class ReportProjectDTO(BaseModel):
    id: int
    project_config_id: int
    report_id: int

class AffectedVulnerDTO(AffectedDTO):
    vulners: list[str]

class ProjectVulnersGetDTO(BaseModel):
    project_id: int
    affected: list[AffectedVulnerDTO]

class ReportAddDTO(BaseModel):
    scan_config_id: int
    projects: list[AffectedProjectDTO] | None

class ReportGetDTO(BaseModel):
    id: int
    created_at: str | None
    scan_config_id: int

class TableReportDTO(BaseModel):
    report_id: c.Link
    created_at: str
    scan_conf_id: c.Link

class ReportAffectDTO(BaseModel):
    affected: AffectedGetDTO
    vulner: VulnerGetDTO

class ReportProjectAffectsDTO(BaseModel):
    project: ProjectConfigGetDTO
    affects: list[ReportAffectDTO]

class ReportFullDTO(ReportGetDTO):
    affects_projects: list[ReportProjectAffectsDTO]
    scan_config: ScanConfigGetDTO


class TableAffectWithVulnerDTO(AffectedDTO):
    vulner: c.Link
    score: float | None = None
    severity: str | None = None


def count_vulnerable_interval(affected: AffectedGetDTO) -> str:
    start = '[' if affected.start_condition == 'gte' else '('
    end = ']' if affected.end_condition == 'lte' else ')'
    return f'{start}{affected.start_value}, {affected.end_value}{end}'

class TableAffectWithIntervalDTO(AffectedGetDTO):
    interval: str

class VulnerBasicGetDTO(BaseModel):
    global_identifier: str
    identifier: str | None
    source_name: str | None
    source_url: str | None = None
    score: float | None = None
    severity: str | None = None

class TableVulnerBasicDTO(VulnerBasicGetDTO):
    global_identifier: c.Link
    source_url: c.Link

class VulnersBasicsGetDTO(BaseModel):
    vulners: list[VulnerBasicGetDTO]
    count: int

class AddItemResponseDTO(BaseModel):
    created_item_id: int
