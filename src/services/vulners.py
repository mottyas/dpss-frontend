"""Модуль сервиса работы с базой уязвимостей"""

import requests
from fastui import AnyComponent
from fastui import components as c
from fastui.events import GoToEvent
from fastui.components.display import DisplayLookup

from ui.base import gen_ui_link, base_page
from services.config import BackendServiceConfig, FrontendServiceConfig
from services.utils import count_vulnerable_interval

from schemas.models import (
    VulnersBasicsGetDTO,
    TableAffectWithIntervalDTO,
    TableVulnerBasicDTO,
    TableRatingDTO,
    VulnerGetDTO,
)


class VulnersService:


    def __init__(self):
        pass

    def get_vulners_base_info(self, page: int = 1, page_size: int = 10) -> VulnersBasicsGetDTO:
        """
        Метод получения данных об уязвимостях в табличном виде

        :param page: Номер страницы пагинации
        :param page_size: Количество записей на одной странице
        :return: Данные записей об уязвимостях из бэкенда
        """

        response_data = requests.get(
            url=BackendServiceConfig.get_vulners_url(),
            params=dict(page=page, page_size=page_size),
        ).json()

        vulners_dto = VulnersBasicsGetDTO.model_validate(response_data)

        return vulners_dto

    def get_view_vulners(self, page: int = 1, page_size: int = 10) -> list[AnyComponent]:
        """
        Метод получения страницы со списком уязвимостей

        :param page: Номер страницы пагинации
        :param page_size: Количество записей на одной странице
        :return: Список компонентов для отрисовки в браузере
        """

        vulners_dto = self.get_vulners_base_info(page, page_size)

        vulners = [
            TableVulnerBasicDTO(
                global_identifier=gen_ui_link(
                    url=FrontendServiceConfig.get_vulner(row.global_identifier),
                    text=row.global_identifier
                ),
                identifier=row.identifier,
                source_name=row.source_name,
                source_url=gen_ui_link(row.source_url),
                score=row.score,
                severity=row.severity,
            )
            for row in vulners_dto.vulners
        ]

        components = [
            c.Heading(text=f'База знаний уязвимостей', level=3),
            c.Table(
                data=vulners,
                data_model=TableVulnerBasicDTO,
                columns=[
                    DisplayLookup(field='global_identifier', table_width_percent=10,
                                  title='Идентификатор уязвимости (БЗУ)'),
                    DisplayLookup(field='identifier', table_width_percent=10, title='Идентификатор уязвимости'),
                    DisplayLookup(field='source_name', table_width_percent=10, title='Имя источника'),
                    DisplayLookup(field='source_url', table_width_percent=10, title='Ссылка на источник'),
                    DisplayLookup(field='score', table_width_percent=10, title='Оценка опасности'),
                    DisplayLookup(field='severity', table_width_percent=10, title='Уровень угрозы'),
                ]
            ),
            c.Pagination(page=page, page_size=page_size, total=vulners_dto.count),
        ]

        return base_page(
            *components,
            title=f'Уязвимость: База знаний уязвимостей',
        )

    def get_vulner_info(self, vulner_id: str) -> VulnerGetDTO:
        """
        Метод получения данных об уязвимости

        :param vulner_id: Идентификатор уязвимости
        :return: Информация об уязвимости
        """

        response = requests.get(url=BackendServiceConfig.get_vulner_url(vulner_id)).json()

        vulner_dto = VulnerGetDTO.model_validate(response)

        return vulner_dto

    def get_view_vulner(self, item_id):
        vulner_dto = self.get_vulner_info(item_id)

        rating_data = [
            TableRatingDTO(
                score=rating_item.score,
                severity=rating_item.severity,
                vector=rating_item.vector,
                source_name=rating_item.source_name,
                source_url=gen_ui_link(url=rating_item.source_url, text=rating_item.source_url),
            )
            for rating_item in vulner_dto.ratings
        ]

        ratings = []
        for rating in vulner_dto.ratings:
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
            for affect in vulner_dto.affected
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
        for reference in vulner_dto.references:
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

        vulner_content = (
            c.Paragraph(text=f'Описание:'),
            c.Paragraph(text=vulner_dto.description),

            c.Paragraph(text=f'Источник: {vulner_dto.source_name}'),
            c.Text(text=f'Ссылка на источник: '),
            c.Link(
                components=[
                    c.Text(text=vulner_dto.source_url)
                ],
                on_click=GoToEvent(url=vulner_dto.source_url)
            ),
            c.Paragraph(text=''),
            c.Heading(text=f'Рейтинг уязвимости', level=4),
            *ratings,
            c.Heading(text=f'Уязвимое ПО', level=4),
            *affects,
            c.Heading(text=f'Дополнительные ресурсы', level=4),
            *references,
        )

        return base_page(
            *vulner_content,
            title=f'Уязвимость: {vulner_dto.global_identifier}',
        )
