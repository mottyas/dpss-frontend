
from datetime import date
from typing import Annotated

import requests
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastui import FastUI, AnyComponent, prebuilt_html, components as c
from fastui.components.display import DisplayMode, DisplayLookup
from fastui.events import GoToEvent, BackEvent
from fastui.forms import fastui_form
from pydantic import BaseModel, Field
import uvicorn

from config import BackendServiceConfig as bsc
from const import BASE_NAVBAR
from forms import ScanConfAddForm
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
    AffectedGetDTO,
    TableAffectWithIntervalDTO,
    VulnerBasicGetDTO,
    count_vulnerable_interval,
)

app = FastAPI()


@app.get('/api/', response_model=FastUI, response_model_exclude_none=True)
def get_index() -> list[AnyComponent]:

    return [
        BASE_NAVBAR,
        c.Page(
            components=[
                c.Link(
                    components=[c.Text(text='Вернуться назад')], on_click=BackEvent()
                ),
            ]
        ),
    ]


class FilterReportForm(BaseModel):
    severity: str = Field(json_schema_extra={'search_url': '/api/forms/search', 'placeholder': 'Filter by Country...'})


@app.get('/api/reports', response_model=FastUI, response_model_exclude_none=True)
def get_reports(page: int = 1, severity: str | None = None) -> list[AnyComponent]:
    """Получение списка отчетов"""

    vulners = ReportTableData
    page_size = 2
    return [
        BASE_NAVBAR,
        c.Page(
            components=[
                c.Link(
                    components=[c.Text(text='Вернуться назад')], on_click=BackEvent()
                ),
                c.Heading(text='Собранные отчеты', level=3),
                c.Table(
                    data=vulners[(page - 1) * page_size: page * page_size],
                    data_model=Report,
                    columns=[
                        DisplayLookup(field='id', on_click=GoToEvent(url='./{id}'), table_width_percent=10),
                        DisplayLookup(field='name', table_width_percent=10),
                        DisplayLookup(field='description', table_width_percent=10),
                    ]
                ),
                c.Pagination(page=page, page_size=page_size, total=len(vulners)),
            ]
        ),
    ]

@app.get('/api/reports/{report_id}', response_model=FastUI, response_model_exclude_none=True)
def get_report(report_id: int) -> list[AnyComponent]:
    """Получение отчета по идентификатору"""

    report = requests.get(bsc.service_url(f'scan/reports/id/{report_id}')).json()

    report_dto = ReportFullDTO.model_validate(report)

    result_affects = []
    for project in report_dto.affects_projects:
        affects = [
            TableAffectWithVulnerDTO.model_validate(
                dict(
                    # vulner=affect.vulner.global_identifier,
                    vulner=c.Link(
                        components=[
                            c.Text(text=affect.vulner.global_identifier),

                        ],
                        on_click=GoToEvent(url=f'/vulners/{affect.vulner.global_identifier}'),
                    ),
                    **dict(affect.affected)
                )
            )
            for affect in project.affects
        ]
        result_affects.extend(
            [
                c.Heading(text=f'Имя проекта: {project.project.name}', level=4),
                c.Paragraph(text=f'Тип проекта: {project.project.type}'),
                c.Table(
                    data=affects,
                    data_model=TableAffectWithVulnerDTO,
                    columns=[
                        DisplayLookup(field='name', table_width_percent=10),
                        DisplayLookup(field='vendor', table_width_percent=10),
                        DisplayLookup(field='type', table_width_percent=10),
                        DisplayLookup(field='vulner', table_width_percent=10),
                    ]
                )
            ]
        )

    scan_conf_link = c.Link(
        components=[
            c.Text(text=report_dto.scan_config.name or str(report_dto.scan_config_id)),

        ],
        on_click=GoToEvent(url=f'/scan/confs/id/{report_dto.scan_config_id}'),
    )
    report_main_data = [
        c.Heading(text=f'Отчет по результатам сканирования', level=3),
        c.Paragraph(text=f'Дата создания отчета: {fix_date_str(report_dto.created_at)}'),
        c.Text(text=f'Используемая конфигурация сканирования: '),
        scan_conf_link,
        c.Paragraph(text=f'Сканируемый хост: {report_dto.scan_config.host}'),
        c.Paragraph(text=f'Используемый пользователь: {report_dto.scan_config.user}'),
        c.Paragraph(text=f'Описание конфигурации:'),
        c.Paragraph(text=f'{report_dto.scan_config.description}'),
        *result_affects,
    ]

    return [
        BASE_NAVBAR,

        c.Page(
            components=[
                c.Link(
                    components=[c.Paragraph(text='Вернуться назад')], on_click=BackEvent()
                ),
                c.PageTitle(text='Отчет пользователя'),
                *report_main_data
            ]
        )
    ]

def fix_date_str(raw_date: str = '10_06_2025_14_14_07') -> str:
    fixed_date = '.'.join(raw_date.split('_')[:3]) + ' ' + ':'.join(raw_date.split('_')[3:])
    return fixed_date

@app.get('/api/vulners', response_model=FastUI, response_model_exclude_none=True)
def get_vulner_data(page: int = 1, page_size = 10) -> list[AnyComponent]:
    response = requests.get(url=bsc.service_url(f'scan/vulners')).json()
    vulners_data = [VulnerBasicGetDTO.model_validate(row) for row in response]

    return [
        BASE_NAVBAR,

        c.Page(
            components=[
                c.Link(
                    components=[c.Paragraph(text='Вернуться назад')], on_click=BackEvent()
                ),
                c.PageTitle(text=f'База знаний уязвимостей'),
                c.Heading(text=f'База знаний уязвимостей', level=3),
                c.Table(
                    data=vulners_data[(page - 1) * page_size: page * page_size],
                    data_model=VulnerBasicGetDTO,
                    columns=[
                        DisplayLookup(field='global_identifier', table_width_percent=10, title='Идентификатор уязвимости (БЗУ)'),
                        DisplayLookup(field='identifier', table_width_percent=10, title='Идентификатор уязвимости'),
                        DisplayLookup(field='source_name', table_width_percent=10, title='Имя источника'),
                        DisplayLookup(field='source_url', table_width_percent=10, title='Ссылка на источник'),
                        DisplayLookup(field='score', table_width_percent=10, title='Оценка опасности'),
                        DisplayLookup(field='severity', table_width_percent=10, title='Уровень угрозы'),
                    ]
                ),
                c.Pagination(page=page, page_size=page_size, total=len(vulners_data)),
                # *vulner_content,
            ]
        )
    ]

@app.get('/api/vulners/{item_id}', response_model=FastUI, response_model_exclude_none=True)
def get_vulner_data(item_id: str) -> list[AnyComponent]:
    response = requests.get(url=bsc.service_url(f'scan/vulners/{item_id}')).json()
    vulner_data = VulnerGetDTO.model_validate(response)

    ratings = []
    for rating in vulner_data.ratings:
        ratings.extend(
            [
                c.Paragraph(text=f'Метод оценки: {rating.method}'),
                c.Paragraph(text=f'Версия метода: {rating.version}'),
                c.Table(
                    data=vulner_data.ratings,
                    data_model=RatingGetDTO,
                    columns=[
                        DisplayLookup(field='score', table_width_percent=10),
                        DisplayLookup(field='severity', table_width_percent=10),
                        DisplayLookup(field='vector', table_width_percent=10),
                        DisplayLookup(field='source_name', table_width_percent=10),
                        DisplayLookup(field='source_url', table_width_percent=10),
                    ]
                )
            ]
        )

    affected = [
        TableAffectWithIntervalDTO(
            interval=count_vulnerable_interval(affected=affect),
            **dict(affect),
        )
        for affect in vulner_data.affected
    ]
    affects = [
        c.Table(
            data=affected,
            data_model=TableAffectWithIntervalDTO,
            columns=[
                DisplayLookup(field='name', table_width_percent=10, title='Имя пакета'),
                DisplayLookup(field='vendor', table_width_percent=10, title='Имя вендора'),
                DisplayLookup(field='type', table_width_percent=10, title='Тип пакета'),
                DisplayLookup(field='interval', table_width_percent=10, title='Диапазон уязвимых версий'),
            ]
        )
    ]

    references = []
    for reference in vulner_data.references:
        references.extend(
            [
                c.Text(text=f'{reference.source}: '),
                c.Link(
                    components=[
                        c.Text(text=reference.url)
                    ],
                    on_click=GoToEvent(url=reference.url)
                ),
                c.Paragraph(text='')
            ]
        )

    vulner_content = [
        c.Paragraph(text=f'Описание:'),
        c.Paragraph(text=vulner_data.description),

        c.Paragraph(text=f'Источник: {vulner_data.source_name}'),
        c.Text(text=f'Ссылка на источник: '),
        c.Link(
            components=[
                c.Text(text=vulner_data.source_url)
            ],
            on_click=GoToEvent(url=vulner_data.source_url)
        ),
        c.Paragraph(text=''),
        c.Heading(text=f'Рейтинг уязвимости', level=4),
        *ratings,
        c.Heading(text=f'Уязвимое ПО', level=4),
        *affects,
        c.Heading(text=f'Дополнительные ресурсы', level=4),
        *references,
    ]

    return [
        BASE_NAVBAR,

        c.Page(
            components=[
                c.Link(
                    components=[c.Paragraph(text='Вернуться назад')], on_click=BackEvent()
                ),
                c.PageTitle(text=f'Уязвимость: {vulner_data.global_identifier}'),
                c.Heading(text=f'Уязвимость {vulner_data.global_identifier}'),
                *vulner_content,
            ]
        )
    ]


@app.get('/api/scan/configs', response_model=FastUI, response_model_exclude_none=True)
def get_scan_configs(page: int = 1, severity: str | None = None) -> list[AnyComponent]:
    vulners = ScanConfTableData
    page_size = 2

    scan_confs = requests.get(url=bsc.service_url('scan/confs/all')).json()
    scan_confs = [ScanConfigGetDTO(**row) for row in scan_confs]

    return [
        BASE_NAVBAR,
        c.Page(
            components=[
                c.Link(
                    components=[c.Text(text='Вернуться назад')], on_click=BackEvent()
                ),
                c.Heading(text='Конфигурации сканирования', level=3),
                c.Table(
                    data=vulners[(page - 1) * page_size: page * page_size],
                    data_model=ScanConf,
                    columns=[
                        DisplayLookup(field='id', on_click=GoToEvent(url='./{id}'), table_width_percent=10),
                        DisplayLookup(field='name', table_width_percent=10),
                        DisplayLookup(field='description', table_width_percent=10),
                    ]
                ),
                c.Pagination(page=page, page_size=page_size, total=len(vulners)),
                c.Button(text='Добавить конфигурацию', on_click=GoToEvent(url='/scan/configs/add')),
            ]
        ),
    ]

@app.get('/api/scan/configs/add', response_model=FastUI, response_model_exclude_none=True)
def add_new_scan_config() -> list[AnyComponent]:
    return [
        BASE_NAVBAR,
        c.Page(
            components=[
                c.Link(
                    components=[c.Text(text='Вернуться назад')], on_click=BackEvent()
                ),
                c.Heading(text='Добавить конфигурацию', level=2),
                c.ModelForm(
                    model=ScanConfAddForm,
                    display_mode='page',
                    submit_url='/api/scan/configs/aa',
                )
            ]
        ),
    ]

@app.get('/api/scan/configs/{conf_id}', response_model=FastUI, response_model_exclude_none=True)
def get_scan_config(conf_id: int) -> list[AnyComponent]:
    """Получение отчета по идентификатору"""

    scan_conf = requests.get(url=bsc.service_url(f'scan/confs/id/{conf_id}')).json()
    scan_conf = ScanConfigGetDTO(**scan_conf)

    return [
        BASE_NAVBAR,
        c.Page(
            components=[
                c.Link(
                    components=[c.Text(text='Вернуться назад')], on_click=BackEvent()
                ),
                c.PageTitle(text='Конфигурация пользователя'),
                c.Heading(text=f'Конфигурация {scan_conf.name}', level=2),
                c.Heading(text='Описание конфигурации сканирования:', level=4),
                c.Text(text=f'{scan_conf.description}'),
                c.Heading(text=f'Имя пользователя: {scan_conf.user}', level=6),
                c.Heading(text=f'Сканируемый хост: {scan_conf.host}', level=6),
                c.Heading(text=f'Пароль пользователя: {scan_conf.secret}', level=6),
                c.Button(text='Удалить'),
                c.Button(text='Изменить', html_type='button'),
            ]
        )
    ]

@app.post('/api/scan/configs/aa', response_model=FastUI, response_model_exclude_none=True)
def add_new_scan_config(form: Annotated[ScanConfAddForm, fastui_form(ScanConfAddForm)]) -> None:
    """Добавление новой конфигурации сканирования"""

    print(f'{form=}')

    ScanConfTableData.append(
        ScanConf(id=len(ScanConfTableData) +  1, **form.model_dump())
    )

    return [c.FireEvent(event=GoToEvent(url='/scan/configs'))]


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
        log_level='debug',
        workers=1,
    )
