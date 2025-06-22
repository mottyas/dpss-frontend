from typing import Annotated

import requests

from fastapi import APIRouter
from fastui import FastUI, AnyComponent, prebuilt_html, components as c
from fastui.components.display import DisplayMode, DisplayLookup
from fastui.events import GoToEvent, BackEvent, PageEvent
from fastui.forms import fastui_form
from pydantic import BaseModel, Field


from config import BackendServiceConfig as bsc
# from const import BASE_NAVBAR
from ui.base import BASE_NAVBAR, base_navbar, base_page
from forms import (
    ScanConfAddForm,
    ProjectScanConfAddForm,
    RunScannerForm,
)
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

scan_router = APIRouter(prefix="/api/scan")


@scan_router.get('/configs', response_model=FastUI, response_model_exclude_none=True)
def get_scan_configs(page: int = 1, page_size: int = 7) -> list[AnyComponent]:

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

    components = [
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

    return base_page(
        *components,
        title='Конфигурации сканирования',
    )

@scan_router.get('/configs/add', response_model=FastUI, response_model_exclude_none=True)
def add_new_scan_config() -> list[AnyComponent]:

    components = [
        c.ModelForm(
            model=ScanConfAddForm,
            display_mode='page',
            submit_url='/api/scan/configs/add',
        )
    ]

    return base_page(
        *components,
        title='Добавить конфигурацию',
    )

# @app.get('/api/scan/confs/{scan_id}/projects/{project_id}', response_model=FastUI, response_model_exclude_none=True)
@scan_router.get('/projects/{project_id}', response_model=FastUI, response_model_exclude_none=True)
def get_project_config(project_id: int) -> list[AnyComponent]:
    project_conf = requests.get(url=bsc.service_url(f'scan/projects/{project_id}')).json()
    project_conf = ProjectConfigGetDTO(**project_conf)

    components = [
        c.Heading(text=f'Тип проекта: {project_conf.type}', level=4),
        c.Heading(text='Описание конфигурации сканирования:', level=4),
        c.Text(text=f'{project_conf.description}'),
        c.Paragraph(text=' '),
        c.Button(text='Удалить'),
        c.Text(text=' '),
        c.Button(text='Изменить', html_type='button'),
    ]

    return base_page(
        *components,
        title=f'Конфигурация проекта "{project_conf.name}"',
    )

@scan_router.get('/configs/{conf_id}', response_model=FastUI, response_model_exclude_none=True)
def get_scan_config(conf_id: int, page: int = 1, page_size: int = 7) -> list[AnyComponent]:
    """Получение отчета по идентификатору"""

    headers = {
        'Content-Type': 'application/json',
        'accept': 'application/json',
    }
    scan_conf = requests.get(url=bsc.service_url(f'scan/confs/id/{conf_id}'), headers=headers).json()
    scan_conf = ScanConfigGetDTO(**scan_conf)

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
        ]
    )

    components = [
        c.Heading(text='Описание конфигурации сканирования:', level=4),
        c.Text(text=f'{scan_conf.description}'),
        c.Paragraph(text=''),
        c.Heading(text=f'Имя пользователя: {scan_conf.user}', level=6),
        c.Heading(text=f'Сканируемый хост: {scan_conf.host}', level=6),
        c.Heading(text=f'Пароль пользователя: {scan_conf.secret}', level=6),
        c.Button(
            text='Удалить',
            on_click=PageEvent(name='static-modal'),
        ),
        c.Text(text=' '),
        c.Button(text='Изменить', html_type='button'),
        c.Text(text=' '),
        c.Button(text='Добавить проект', html_type='button',
                 on_click=GoToEvent(url=f'/scan/configs/{conf_id}/add_project')),
        c.Text(text=' '),
        c.Div(
            components=[
                c.Text(text='Запуск сканирования: '),
                c.ModelForm(
                    model=RunScannerForm,
                    display_mode='default',
                    submit_url=f'/api/scan/run/{conf_id}',
                )
            ]
        ),
        c.Paragraph(text=' '),
        project_confs_table,
        c.Pagination(page=page, page_size=page_size, total=len(table_data)),
        c.Modal(
            title='Some static modal',
            body=[c.Paragraph(text='This is some static content that was set when the modal was defined.')],
            footer=[
                c.Button(text='Close', on_click=PageEvent(name='static-modal', clear=True)),
            ],
            open_trigger=PageEvent(name='static-modal'),
        ),
    ]

    return base_page(
        *components,
        title=f'Конфигурация "{scan_conf.name}"',
    )


@scan_router.post('/run/{conf_id}', response_model=FastUI, response_model_exclude_none=True)
def run_scanner(conf_id: int, form: Annotated[RunScannerForm, fastui_form(RunScannerForm)]) -> list[AnyComponent]:

    headers = {
        'accept': 'application/json',
    }

    response = requests.post(url=bsc.service_url(f'scan/run/{conf_id}'), headers=headers) #, json=data.model_dump(mode='json'))
    validated_response = AddItemResponseDTO.model_validate(response.json())

    return [c.FireEvent(event=BackEvent())]


@scan_router.post('/configs/{conf_id}/add_project', response_model=FastUI, response_model_exclude_none=True)
def add_new_scan_project_config(conf_id: int, form: Annotated[ProjectScanConfAddForm, fastui_form(ProjectScanConfAddForm)]) -> list[AnyComponent]:

    data = ProjectScanConfigAddDTO(
        name=form.name,
        type=form.type.value,
        dir_path=form.dir_path,
        description=form.description,
        scan_config_id=conf_id,
    )

    headers = {
        'Content-Type': 'application/json',
        'accept': 'application/json',
    }

    response = requests.post(url=bsc.service_url(f'scan/projects'), headers=headers, json=data.model_dump(mode='json'))
    validated_response = AddItemResponseDTO.model_validate(response.json())

    return [c.FireEvent(event=GoToEvent(url=f'/scan/projects/{validated_response.created_item_id}'))]


@scan_router.get('/configs/{conf_id}/add_project', response_model=FastUI, response_model_exclude_none=True)
def add_new_scan_project_config_form(conf_id: int) -> list[AnyComponent]:
    components = [
        c.Link(
            components=[c.Text(text='Вернуться назад')], on_click=BackEvent()
        ),
        c.Heading(text='Добавить конфигурацию проекта', level=2),
        c.ModelForm(
            model=ProjectScanConfAddForm,
            display_mode='page',
            submit_url=f'/api/scan/configs/{conf_id}/add_project',
        )
    ]

    return base_page(
        *components,
        title='Добавить конфигурацию проекта',
    )

@scan_router.post('/configs/add', response_model=FastUI, response_model_exclude_none=True)
def add_new_scan_config(form: Annotated[ScanConfAddForm, fastui_form(ScanConfAddForm)]) -> list[c.FireEvent]:
    """Добавление новой конфигурации сканирования"""

    kek = dict(form)

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
    validated_response = AddItemResponseDTO.model_validate(response.json())

    return [c.FireEvent(event=GoToEvent(url=f'/scan/configs/{validated_response.created_item_id}'))]
