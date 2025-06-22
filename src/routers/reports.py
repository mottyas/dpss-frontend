
import requests

from fastapi import APIRouter
from fastui import FastUI, AnyComponent, prebuilt_html, components as c
from fastui.components.display import DisplayMode, DisplayLookup
from fastui.events import GoToEvent, BackEvent, PageEvent
from fastui.forms import fastui_form
from pydantic import BaseModel, Field


from config import BackendServiceConfig as bsc
# from const import BASE_NAVBAR
from ui.base import base_navbar, base_page
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

report_router = APIRouter(prefix="/api/reports")



@report_router.get('/', response_model=FastUI, response_model_exclude_none=True)
def get_reports(page: int = 1, page_size: int = 10) -> list[AnyComponent]:
    """Получение списка отчетов"""

    reports_response = requests.get(url=bsc.service_url('scan/reports')).json()

    reports = [
        ReportGetDTO.model_validate(row)
        for row in reports_response
    ]

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

    components=[
        table,
        c.Pagination(page=page, page_size=page_size, total=len(reports)),
    ]

    return base_page(
        *components,
        title='Собранные отчеты',
    )

@report_router.get('/{report_id}', response_model=FastUI, response_model_exclude_none=True)
def get_report(report_id: int, page: int = 1) -> list[AnyComponent]:
    """Получение отчета по идентификатору"""
    page_size = 10

    report = requests.get(bsc.service_url(f'scan/reports/id/{report_id}')).json()

    report_dto = ReportFullDTO.model_validate(report)

    result_affects = []
    # print(f'{report_dto.affects_projects=}')
    print(f'{len(report_dto.affects_projects)=}')
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
                    data=affects[(page - 1) * page_size: page * page_size],
                    data_model=TableAffectWithVulnerDTO,
                    columns=[
                        DisplayLookup(field='name', table_width_percent=10),
                        DisplayLookup(field='vendor', table_width_percent=10),
                        DisplayLookup(field='type', table_width_percent=10),
                        DisplayLookup(field='vulner', table_width_percent=10),
                        DisplayLookup(field='score', table_width_percent=10),
                        DisplayLookup(field='severity', table_width_percent=10),
                    ]
                ),
                c.Pagination(page=page, page_size=page_size, total=len(affects)),

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
        # c.Pagination(page=page, page_size=page_size, total=len(report_dto.affects_projects)),

    ]

    components=[
        # c.Link(
        #     components=[c.Paragraph(text='Вернуться назад')], on_click=BackEvent()
        # ),
        # c.PageTitle(text='Отчет пользователя'),
        *report_main_data,
        c.Button(text='Удалить'),
        c.Text(text=' '),
        c.Button(text='Экспорт'),
    ]

    return base_page(
        *components,
        title='Отчет пользователя',
    )
