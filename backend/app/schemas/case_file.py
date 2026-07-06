from datetime import datetime
from typing import Any

from pydantic import BaseModel

from ..models.case_file import PipelineStatus


class CaseFileSummary(BaseModel):
    case_id: str
    pipeline_status: PipelineStatus
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class CaseFileDetail(CaseFileSummary):
    data: dict[str, Any]


class CaseListItem(BaseModel):
    case_id: str
    sample_name: str
    route: str
    pipeline_status: PipelineStatus
    created_at: datetime


class AnalyzeResponse(BaseModel):
    case_id: str
    message: str
