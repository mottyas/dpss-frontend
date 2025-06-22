import logging
from datetime import date
from typing import Annotated

import requests
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastui import FastUI, AnyComponent, prebuilt_html, components as c
from fastui.components.display import DisplayMode, DisplayLookup
from fastui.events import GoToEvent, BackEvent, PageEvent
from fastui.forms import fastui_form
from pydantic import BaseModel, Field

from routers.reports import report_router
from routers.vulners import vulners_router
from routers.sandbox import sandbox_router
from routers.scans import scan_router
from config import BackendServiceConfig as bsc
from const import BASE_NAVBAR, INDEX_PAGE_TEXT
from forms import (
    ScanConfAddForm,
    ProjectScanConfAddForm,
    RunScannerForm,
)
from ui.base import base_page
from functions import gen_go_to_link
from templates import (
    VulnerTableData,
    ReportTableData,
    ScanConfTableData,
    Report,
    Vulner,
    ScanConf,
)
from models import (
    ScanConfigGetDTO,
    ReportFullDTO,
    ReportAffectDTO,
    TableAffectWithVulnerDTO,
    VulnerGetDTO,
    RatingGetDTO,
    ProjectScanConfigAddDTO,
    TableProjectConfigGetDTO,
    ProjectConfigGetDTO,
    AffectedGetDTO,
    ReportGetDTO,
    TableReportDTO,
    TableAffectWithIntervalDTO,
    TableVulnerBasicDTO,
    TableScanConfigDTO,
    TableRatingDTO,
    VulnerBasicGetDTO,
    VulnersBasicsGetDTO,
    AddItemResponseDTO,
    ScanConfigAddDTO,
    count_vulnerable_interval,
)

app = FastAPI()

# Подключение маршрутов.
routers = [
    report_router,
    vulners_router,
    scan_router,
    sandbox_router,
]

for router in routers:
    app.include_router(router)


@app.get('/api/', response_model=FastUI, response_model_exclude_none=True)
def get_index() -> list[AnyComponent]:
    components = [
        c.Link(
            components=[c.Text(text='Вернуться назад')], on_click=BackEvent()
        ),
        c.Paragraph(text=''),
        c.Markdown(
            text=INDEX_PAGE_TEXT,
        ),
    ]

    return base_page(*components)

    # return [
    #     BASE_NAVBAR,
    #     c.Page(
    #         components=[
    #             c.Link(
    #                 components=[c.Text(text='Вернуться назад')], on_click=BackEvent()
    #             ),
    #             c.Paragraph(text=''),
    #             c.Markdown(
    #                 text=INDEX_PAGE_TEXT,
    #             ),
    #         ]
    #     ),
    # ]


# class FilterReportForm(BaseModel):
#     severity: str = Field(json_schema_extra={'search_url': '/api/forms/search', 'placeholder': 'Filter by Country...'})
#
#
# def fix_date_str(raw_date: str = '10_06_2025_14_14_07') -> str:
#     fixed_date = '.'.join(raw_date.split('_')[:3]) + ' ' + ':'.join(raw_date.split('_')[3:])
#     return fixed_date


@app.get('/{path:path}')
async def html_landing() -> HTMLResponse:
    """Simple HTML page which serves the React app, comes last as it matches all paths."""
    return HTMLResponse(prebuilt_html(title='DPSS Service'))

if __name__ == '__main__':
    uvicorn.run(
        app='main:app',
        host='0.0.0.0',
        port=8002,
        reload=True,
        log_level='info',
        workers=1,
    )
