"""Модуль сервиса работы с отчетами"""

import requests
from fastui import AnyComponent
from fastui import components as c
from fastui.events import GoToEvent
from fastui.components.display import DisplayLookup

from ui.base import gen_ui_link, base_page
from services.config import BackendServiceConfig, FrontendServiceConfig
from services.utils import fix_date_str
from schemas.models import (
    TableAffectWithVulnerDTO,
    ReportGetDTO,
    TableReportDTO,
    ReportFullDTO,
)


class ReportsService:

    def __init__(self):
        pass

    def get_reports_info(self) -> list[ReportGetDTO]:
        """
        Метод получения списка отчетов

        :return: Список отчетов
        """

        reports_response = requests.get(url=BackendServiceConfig.get_reports_url()).json()

        reports = [
            ReportGetDTO.model_validate(row)
            for row in reports_response
        ]

        return reports

    def get_reports_view(self, page: int = 1, page_size: int = 10) -> list[AnyComponent]:
        """
        Метод получения страницы с отчетами

        :param page: Номер страницы пагинации
        :param page_size: Количество записей на одной странице
        :return: Страница с информацией об отчетах
        """

        reports = self.get_reports_info()

        table_reports = [
            TableReportDTO(
                report_id=gen_ui_link(
                    url=FrontendServiceConfig.get_report(report.id),
                    text=report.id,
                ),
                created_at=fix_date_str(report.created_at),
                scan_conf_id=gen_ui_link(
                    url=FrontendServiceConfig.get_scan_config(report.scan_config_id),
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

    def get_report_info(self, report_id: int) -> ReportFullDTO:
        """
        Метод получения информации из отчета

        :param report_id: Идентификатор отчета
        :return: Информация об отчете
        """

        report = requests.get(url=BackendServiceConfig.get_report_url(report_id)).json()

        report_dto = ReportFullDTO.model_validate(report)

        return report_dto

    def get_report_view(self, report_id: int, page: int = 1, page_size: int = 10):
        """
        Метод получения информации из отчета

        :param report_id: Идентификатор отчета
        :param page: Номер страницы пагинации
        :param page_size: Количество записей на одной странице
        :return: Страница с информацией об отчете сканирования
        """

        report_dto = self.get_report_info(report_id)

        result_affects = []
        for project in report_dto.affects_projects:
            affects = [
                TableAffectWithVulnerDTO.model_validate(
                    dict(
                        vulner=c.Link(
                            components=[
                                c.Text(text=affect.vulner.global_identifier),

                            ],
                            on_click=GoToEvent(
                                url=FrontendServiceConfig.get_vulner(affect.vulner.global_identifier)
                            ),
                        ),
                        score=affect.vulner.ratings[0].score if affect.vulner.ratings else None,
                        severity=affect.vulner.ratings[0].severity if affect.vulner.ratings else None,
                        **dict(affect.affected)
                    )
                )
                for affect in project.affects
            ]
            affects.sort(key=lambda x: (x.score is None, x.score))
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
            on_click=GoToEvent(
                url=FrontendServiceConfig.get_scan_config(report_dto.scan_config_id)
            ),
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

        components = [
            *report_main_data,
            c.Button(text='Удалить'),
            c.Text(text=' '),
            c.Button(text='Экспорт'),
        ]

        return base_page(
            *components,
            title='Отчет пользователя',
        )
