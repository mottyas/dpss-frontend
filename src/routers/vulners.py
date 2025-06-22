
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

vulners_router = APIRouter(prefix="/api/vulners")


@vulners_router.get('/', response_model=FastUI, response_model_exclude_none=True)
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

    # return [
    #     base_navbar(),
    #
    #     c.Page(
    #         components=[
    #             c.Link(
    #                 components=[c.Paragraph(text='Вернуться назад')], on_click=BackEvent()
    #             ),
    #             c.PageTitle(text=f'База знаний уязвимостей'),
    #             c.Heading(text=f'База знаний уязвимостей', level=3),
    #             c.Table(
    #                 data=vulners,
    #                 data_model=TableVulnerBasicDTO,
    #                 columns=[
    #                     DisplayLookup(field='global_identifier', table_width_percent=10, title='Идентификатор уязвимости (БЗУ)'),
    #                     DisplayLookup(field='identifier', table_width_percent=10, title='Идентификатор уязвимости'),
    #                     DisplayLookup(field='source_name', table_width_percent=10, title='Имя источника'),
    #                     DisplayLookup(field='source_url', table_width_percent=10, title='Ссылка на источник'),
    #                     DisplayLookup(field='score', table_width_percent=10, title='Оценка опасности'),
    #                     DisplayLookup(field='severity', table_width_percent=10, title='Уровень угрозы'),
    #                 ]
    #             ),
    #             c.Pagination(page=page, page_size=page_size, total=vulners_data.count),
    #         ]
    #     )
    # ]

    components = [
        # c.Link(
        #     components=[c.Paragraph(text='Вернуться назад')], on_click=BackEvent()
        # ),
        # c.PageTitle(text=f'База знаний уязвимостей'),
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

    return base_page(
        *components,
        title=f'Уязвимость: База знаний уязвимостей',
    )


@vulners_router.get('/{item_id}', response_model=FastUI, response_model_exclude_none=True)
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

    vulner_content = (
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
    )
    #
    # return [
    #     base_navbar(),
    #
    #     c.Page(
    #         components=[
    #             c.Link(
    #                 components=[c.Paragraph(text='Вернуться назад')], on_click=BackEvent()
    #             ),
    #             c.PageTitle(text=f'Уязвимость: {vulner_data.global_identifier}'),
    #             c.Heading(text=f'Уязвимость {vulner_data.global_identifier}'),
    #             *vulner_content,
    #         ]
    #     )
    # ]

    return base_page(
        *vulner_content,
        title=f'Уязвимость: {vulner_data.global_identifier}',
    )
