
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
from const import BASE_NAVBAR, INDEX_PAGE_TEXT
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


@app.get('/api/', response_model=FastUI, response_model_exclude_none=True)
def get_index() -> list[AnyComponent]:

    return [
        BASE_NAVBAR,
        c.Page(
            components=[
                c.Link(
                    components=[c.Text(text='Вернуться назад')], on_click=BackEvent()
                ),
                c.Paragraph(text=''),
                c.Markdown(
                    text=INDEX_PAGE_TEXT,
                ),
            ]
        ),
    ]


class FilterReportForm(BaseModel):
    severity: str = Field(json_schema_extra={'search_url': '/api/forms/search', 'placeholder': 'Filter by Country...'})


@app.get('/api/reports', response_model=FastUI, response_model_exclude_none=True)
def get_reports(page: int = 1, severity: str | None = None) -> list[AnyComponent]:
    """Получение списка отчетов"""

    page_size = 2

    reports_response = requests.get(url=bsc.service_url('scan/reports')).json()

    reports = [
        ReportGetDTO.model_validate(row)
        for row in reports_response
    ]

    print(f'{reports=}')

    table_reports = [
        TableReportDTO(
            report_id=gen_go_to_link(
                url=f'/reports/{report.id}',
                text=report.id,
            ),
            created_at=fix_date_str(report.created_at),
            scan_conf_id=gen_go_to_link(
                url=f'/scan/configs/{report.scan_config_id}',
                text=report.scan_config_id,
            ),
        )
        for report in reports
    ]

    table = c.Table(
        data=table_reports[(page - 1) * page_size: page * page_size],
        data_model=TableReportDTO,
        columns=[
            DisplayLookup(field='report_id', table_width_percent=10, title='ID'),
            DisplayLookup(field='created_at', table_width_percent=10, title='Дата создания'),
            DisplayLookup(field='scan_conf_id', table_width_percent=10, title='Конфигурация сканирования'),
        ]
    )

    return [
        BASE_NAVBAR,
        c.Page(
            components=[
                c.Link(
                    components=[c.Text(text='Вернуться назад')], on_click=BackEvent()
                ),
                c.Heading(text='Собранные отчеты', level=3),
                table,
                c.Pagination(page=page, page_size=page_size, total=len(reports)),
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
                    vulner=c.Link(
                        components=[
                            c.Text(text=affect.vulner.global_identifier),

                        ],
                        on_click=GoToEvent(url=f'/vulners/{affect.vulner.global_identifier}'),
                    ),
                    score=affect.vulner.ratings[0].score if affect.vulner.ratings else None,
                    severity=affect.vulner.ratings[0].severity if affect.vulner.ratings else None,
                    **dict(affect.affected)
                )
            )
            for affect in project.affects
        ]
        affects.sort(key=lambda x: (x.score is None, x.score))
        # affects.reverse()
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
                        DisplayLookup(field='score', table_width_percent=10),
                        DisplayLookup(field='severity', table_width_percent=10),
                    ]
                )
            ]
        )

    scan_conf_link = c.Link(
        components=[
            c.Text(text=report_dto.scan_config.name or str(report_dto.scan_config_id)),

        ],
        on_click=GoToEvent(url=f'/scan/configs/{report_dto.scan_config_id}'),
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
                *report_main_data,
                c.Button(text='Удалить'),
                c.Text(text=' '),
                c.Button(text='Экспорт'),
            ]
        )
    ]

def fix_date_str(raw_date: str = '10_06_2025_14_14_07') -> str:
    fixed_date = '.'.join(raw_date.split('_')[:3]) + ' ' + ':'.join(raw_date.split('_')[3:])
    return fixed_date

@app.get('/api/vulners', response_model=FastUI, response_model_exclude_none=True)
def get_vulners(page: int = 1) -> list[AnyComponent]:
    page_size: int = 7
    params = dict(page=page, page_size=page_size)
    response = requests.get(url=bsc.service_url(f'scan/vulners'), params=params).json()
    vulners_data = VulnersBasicsGetDTO.model_validate(response)

    vulners = [
        TableVulnerBasicDTO(
            global_identifier=gen_go_to_link(f'/vulners/{row.global_identifier}', row.global_identifier),
            identifier=row.identifier,
            source_name=row.source_name,
            source_url=gen_go_to_link(row.source_url),
            score=row.score,
            severity=row.severity,
        )
        for row in vulners_data.vulners
    ]

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
                    data=vulners,
                    data_model=TableVulnerBasicDTO,
                    columns=[
                        DisplayLookup(field='global_identifier', table_width_percent=10, title='Идентификатор уязвимости (БЗУ)'),
                        DisplayLookup(field='identifier', table_width_percent=10, title='Идентификатор уязвимости'),
                        DisplayLookup(field='source_name', table_width_percent=10, title='Имя источника'),
                        DisplayLookup(field='source_url', table_width_percent=10, title='Ссылка на источник'),
                        DisplayLookup(field='score', table_width_percent=10, title='Оценка опасности'),
                        DisplayLookup(field='severity', table_width_percent=10, title='Уровень угрозы'),
                    ]
                ),
                c.Pagination(page=page, page_size=page_size, total=vulners_data.count),
            ]
        )
    ]

@app.get('/api/vulners/{item_id}', response_model=FastUI, response_model_exclude_none=True)
def get_vulner_data(item_id: str) -> list[AnyComponent]:
    response = requests.get(url=bsc.service_url(f'scan/vulners/{item_id}')).json()
    vulner_data = VulnerGetDTO.model_validate(response)


    descr = 'Xpdf, as used in products such as gpdf, kpdf, pdftohtml, poppler, teTeX, CUPS, libextractor, and others, allows attackers to cause a denial of service (infinite loop) via streams that end prematurely, as demonstrated using the (1) CCITTFaxDecode and (2) DCTDecode streams, aka "Infinite CPU spins."'
    if vulner_data.global_identifier == 'PyUp.CVE-2005-3625.CVE-2005-3625':
        vulner_data.description = descr

    rating_data = [
        TableRatingDTO(
            score=rating_item.score,
            severity=rating_item.severity,
            vector=rating_item.vector,
            source_name=rating_item.source_name,
            source_url=gen_go_to_link(url=rating_item.source_url, text=rating_item.source_url),
        )
        for rating_item in vulner_data.ratings
    ]

    ratings = []
    for rating in vulner_data.ratings:
        ratings.extend(
            [
                c.Paragraph(text=f'Метод оценки: {rating.method}'),
                c.Paragraph(text=f'Версия метода: {rating.version}'),
                c.Table(
                    data=rating_data,
                    data_model=TableRatingDTO,
                    columns=[
                        DisplayLookup(field='score', table_width_percent=10, title='Оценка в баллах'),
                        DisplayLookup(field='severity', table_width_percent=10, title='Уровень угрозы'),
                        DisplayLookup(field='vector', table_width_percent=10, title='Метрики вектора'),
                        DisplayLookup(field='source_name', table_width_percent=10, title='Источник информации'),
                        DisplayLookup(field='source_url', table_width_percent=10, title='Ссылка на исходные данные'),
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
    # vulners = ScanConfTableData
    page_size = 7

    scan_confs_response = requests.get(url=bsc.service_url('scan/confs/all')).json()
    scan_confs = [
        ScanConfigGetDTO(**row)
        for row in scan_confs_response
    ]

    scan_confs_table = [
        TableScanConfigDTO(
            id=gen_go_to_link(
                url=f'/scan/configs/{scan_conf.id}',
                text=str(scan_conf.id),
            ),
            name=scan_conf.name,
            host=scan_conf.host,
            user=scan_conf.user,
            date=fix_date_str(scan_conf.date),
        )
        for scan_conf in scan_confs
    ]

    return [
        BASE_NAVBAR,
        c.Page(
            components=[
                c.Link(
                    components=[c.Text(text='Вернуться назад')], on_click=BackEvent()
                ),
                c.Heading(text='Конфигурации сканирования', level=3),
                c.Table(
                    data=scan_confs_table,
                    data_model=TableScanConfigDTO,
                    columns=[
                        DisplayLookup(field='id', table_width_percent=10),
                        DisplayLookup(field='name', table_width_percent=10, title='Имя настроек конфигурации'),
                        DisplayLookup(field='host', table_width_percent=10, title='Адрес хоста'),
                        DisplayLookup(field='user', table_width_percent=10, title='Имя пользователя'),
                        DisplayLookup(field='date', table_width_percent=10, title='Дата создания'),
                    ]
                ),
                c.Pagination(page=page, page_size=page_size, total=len(scan_confs)),
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
                    submit_url='/api/scan/configs/add',
                )
            ]
        ),
    ]

# @app.get('/api/scan/confs/{scan_id}/projects/{project_id}', response_model=FastUI, response_model_exclude_none=True)
@app.get('/api/scan/projects/{project_id}', response_model=FastUI, response_model_exclude_none=True)
def get_project_config(project_id: int) -> list[AnyComponent]:
    project_conf = requests.get(url=bsc.service_url(f'scan/projects/{project_id}')).json()
    project_conf = ProjectConfigGetDTO(**project_conf)

    return [
        BASE_NAVBAR,
        c.Page(
            components=[
                c.Link(
                    components=[c.Text(text='Вернуться назад')], on_click=BackEvent()
                ),
                c.PageTitle(text='Конфигурация проекта пользователя'),
                c.Heading(text=f'Конфигурация проекта "{project_conf.name}"', level=2),
                c.Heading(text=f'Тип проекта: {project_conf.type}', level=4),
                c.Heading(text='Описание конфигурации сканирования:', level=4),
                c.Text(text=f'{project_conf.description}'),
                c.Paragraph(text=' '),
                c.Button(text='Удалить'),
                c.Text(text=' '),
                c.Button(text='Изменить', html_type='button'),

            ]
        )
    ]

@app.get('/api/scan/configs/{conf_id}', response_model=FastUI, response_model_exclude_none=True)
def get_scan_config(conf_id: int, page: int = 1) -> list[AnyComponent]:
    """Получение отчета по идентификатору"""

    page_size = 7
    headers = {
        'Content-Type': 'application/json',
        'accept': 'application/json',
    }
    scan_conf = requests.get(url=bsc.service_url(f'scan/confs/id/{conf_id}'), headers=headers).json()
    scan_conf = ScanConfigGetDTO(**scan_conf)

    print(f'{scan_conf=}')

    table_data = [
        TableProjectConfigGetDTO(
            id=gen_go_to_link(url=f'/scan/projects/{row.id}', text=row.id),
            name=row.name,
            type=row.type,
            dir_path=row.dir_path,
            description=row.description,
        )
        for row in scan_conf.projects
    ]

    project_confs_table = c.Table(
        data=table_data[(page - 1) * page_size: page * page_size],
        data_model=TableProjectConfigGetDTO,
        columns=[
            DisplayLookup(field='id', table_width_percent=10, title='ID'),
            DisplayLookup(field='name', table_width_percent=10, title='Имя проекта'),
            DisplayLookup(field='type', table_width_percent=10, title='Тип проекта'),
            # DisplayLookup(field='dir_path', table_width_percent=10, title='Локальный путь'),
        ]
    )

    return [
        BASE_NAVBAR,
        c.Page(
            components=[
                c.Link(
                    components=[c.Text(text='Вернуться назад')], on_click=BackEvent()
                ),
                c.PageTitle(text='Конфигурация пользователя'),
                c.Heading(text=f'Конфигурация "{scan_conf.name}"', level=2),
                c.Heading(text='Описание конфигурации сканирования:', level=4),
                c.Text(text=f'{scan_conf.description}'),
                c.Paragraph(text=''),
                c.Heading(text=f'Имя пользователя: {scan_conf.user}', level=6),
                c.Heading(text=f'Сканируемый хост: {scan_conf.host}', level=6),
                c.Heading(text=f'Пароль пользователя: {scan_conf.secret}', level=6),
                c.Button(text='Удалить'),
                c.Text(text=' '),
                c.Button(text='Изменить', html_type='button'),
                c.Text(text=' '),
                c.Button(text='Добавить проект', html_type='button'),
                c.Text(text=' '),
                c.Button(text='Запуск сканирования', html_type='button'),

                c.Paragraph(text=' '),
                project_confs_table,
                c.Pagination(page=page, page_size=page_size, total=len(table_data)),

            ]
        )
    ]

@app.post('/api/scan/configs/add', response_model=FastUI, response_model_exclude_none=True)
def add_new_scan_config(form: Annotated[ScanConfAddForm, fastui_form(ScanConfAddForm)]) -> list[c.FireEvent]:
    """Добавление новой конфигурации сканирования"""

    print(f'{form=}')
    kek = dict(form)
    print(f'{kek=}')

    data = ScanConfigAddDTO(
        name=form.name,
        host=form.host,
        user=form.user,
        secret=form.password,
        description=form.description,
        port=form.port,
    )

    headers = {
        'Content-Type': 'application/json',
        'accept': 'application/json',
    }

    response = requests.post(url=bsc.service_url('scan/confs'), headers=headers, json=data.model_dump(mode='json'))
    print(f'response.json()={response.json()}')
    validated_response = AddItemResponseDTO.model_validate(response.json())

    return [c.FireEvent(event=GoToEvent(url=f'/scan/configs/{validated_response.created_item_id}'))]


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
