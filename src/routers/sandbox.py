

import requests

from fastapi import APIRouter
from fastui import FastUI, AnyComponent, prebuilt_html, components as c
from fastui.components.display import DisplayMode, DisplayLookup
from fastui.events import GoToEvent, BackEvent, PageEvent
from fastui.forms import fastui_form
from pydantic import BaseModel, Field


from config import BackendServiceConfig as bsc
from const import BASE_NAVBAR
from forms import RunScannerForm
from functions import gen_go_to_link, fix_date_str
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

sandbox_router = APIRouter(prefix="/api/sandbox")




@sandbox_router.get('/', response_model=FastUI, response_model_exclude_none=True)
def get_sandbox() -> list[AnyComponent]:
    """Получение страницы с песочницей"""
    conf_id = 8
    return [
        c.PageTitle(text='DPSS SandBox Demo'),
        BASE_NAVBAR,
        c.Page(
            components=[
                c.Link(
                    components=[c.Text(text='Вернуться назад')], on_click=BackEvent()
                ),
                # c.Div(
                #     components=[
                #         c.Heading(text='Dynamic Modal', level=2),
                #         c.Markdown(
                #             text=(
                #                 'The button below will open a modal with content loaded from the server when '
                #                 "it's opened using `ServerLoad`."
                #             )
                #         ),
                #         c.Button(text='Show Dynamic Modal', on_click=PageEvent(name='run-scanner')),
                #         c.Modal(
                #             title='Dynamic Modal',
                #             body=[c.ServerLoad(path=f'/scan/run/{conf_id}')],
                #             footer=[
                #                 c.Button(text='Close', on_click=PageEvent(name='dynamic-modal', clear=True)),
                #             ],
                #             open_trigger=PageEvent(name='run-scanner'),
                #         ),
                #     ],
                #     class_name='border-top mt-3 pt-1',
                # ),
                c.Paragraph(text=''),

                # c.Div(
                #     components=[
                #         c.Text(text='Запуск сканирования: '),
                #         c.ModelForm(
                #             model=RunScannerForm,
                #             display_mode='default',
                #             submit_url=f'/api/scan/run/{conf_id}',
                #         )
                #     ]
                # )


                # c.Div(
                #     components=[
                #         c.Button(text='Run Scanner', html_type='submit', on_click=PageEvent(name='server-load')),
                #
                #         c.ServerLoad(
                #             path=f'/scan/run/{conf_id}',
                #             load_trigger=PageEvent(name='server-load'),
                #             method='POST',
                #
                #             # components=[c.Text(text='Run Scanner')],
                #         ),
                #     ],
                #     # class_name='py-2',
                # ),
            ]
        ),
        c.Footer(
            extra_text='FastUI Demo',
            links=[
                c.Link(
                    components=[c.Text(text='Github')], on_click=GoToEvent(url='https://github.com/pydantic/FastUI')
                ),
                c.Link(components=[c.Text(text='PyPI')], on_click=GoToEvent(url='https://pypi.org/project/fastui/')),
                c.Link(components=[c.Text(text='NPM')], on_click=GoToEvent(url='https://www.npmjs.com/org/pydantic/')),
            ],
        ),
    ]

