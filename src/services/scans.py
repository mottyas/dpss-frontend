"""Модуль сервиса работы со сканером уязвимостей"""

from typing import Annotated

import requests
from fastui import AnyComponent
from fastui.forms import fastui_form
from fastui import components as c
from fastui.events import GoToEvent, BackEvent
from fastui.components.display import DisplayLookup

from ui.base import gen_ui_link, base_page
from services.config import BackendServiceConfig, FrontendServiceConfig
from services.utils import fix_date_str

from schemas.forms import (
    ScanConfAddForm,
    RunScannerForm,
    ProjectScanConfAddForm,
)
from schemas.models import (
    TableScanConfigDTO,
    ProjectScanConfigAddDTO,
    ProjectConfigGetDTO,
    TableProjectConfigGetDTO,
    ScanConfigAddDTO,
    AddItemResponseDTO,
    ScanConfigGetDTO,
)


class ScannerService:


    def __init__(self):
        pass

    def get_scan_configs_info(self) -> list[ScanConfigGetDTO]:
        scan_confs_response = requests.get(url=BackendServiceConfig.get_configs_url()).json()
        scan_confs = [
            ScanConfigGetDTO(**row)
            for row in scan_confs_response
        ]

        return scan_confs

    def get_scan_configs_view(self, page: int = 1, page_size: int = 7):
        scan_confs = self.get_scan_configs_info()

        scan_confs_table = [
            TableScanConfigDTO(
                id=gen_ui_link(
                    url=FrontendServiceConfig.get_scan_config(scan_conf.id),
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

    def get_scan_config_info(self, conf_id: int) -> ScanConfigGetDTO:
        headers = {
            'Content-Type': 'application/json',
            'accept': 'application/json',
        }

        scan_conf_response = requests.get(
            url=BackendServiceConfig.get_config_url(conf_id),
            headers=headers
        ).json()

        scan_conf = ScanConfigGetDTO(**scan_conf_response)

        return scan_conf

    def get_scan_config_view(self, conf_id: int, page: int = 1, page_size: int = 7) -> list[AnyComponent]:
        scan_conf = self.get_scan_config_info(conf_id)

        table_data = [
            TableProjectConfigGetDTO(
                id=gen_ui_link(url=FrontendServiceConfig.get_scan_project_config(row.id), text=row.id),
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
            ),
            c.Text(text=' '),
            c.Button(text='Изменить', html_type='button'),
            c.Text(text=' '),
            c.Button(text='Добавить проект', html_type='button',
                     on_click=GoToEvent(url=FrontendServiceConfig.add_project_config_url(conf_id))),
            c.Text(text=' '),
            c.Div(
                components=[
                    c.Text(text='Запуск сканирования: '),
                    c.ModelForm(
                        model=RunScannerForm,
                        display_mode='default',
                        submit_url=FrontendServiceConfig.submit_scanner_run_url(conf_id),
                    )
                ]
            ),
            c.Paragraph(text=' '),
            project_confs_table,
            c.Pagination(page=page, page_size=page_size, total=len(table_data)),
        ]

        return base_page(
            *components,
            title=f'Конфигурация "{scan_conf.name}"',
        )


    def add_scan_config(self, form: Annotated[ScanConfAddForm, fastui_form(ScanConfAddForm)]) -> list[AnyComponent]:
        headers = {
            'Content-Type': 'application/json',
            'accept': 'application/json',
        }

        data = ScanConfigAddDTO(
            name=form.name,
            host=form.host,
            user=form.user,
            secret=form.password,
            description=form.description,
            port=form.port,
        )

        response = requests.post(
            url=BackendServiceConfig.add_configs_url(),
            headers=headers,
            json=data.model_dump(mode='json')
        )

        validated_response = AddItemResponseDTO.model_validate(response.json())

        return [c.FireEvent(event=GoToEvent(url=FrontendServiceConfig.get_scan_config(validated_response.created_item_id)))]

    def add_scan_config_view(self):
        components = [
            c.ModelForm(
                model=ScanConfAddForm,
                display_mode='page',
                submit_url=FrontendServiceConfig.submit_add_config_url(),
            )
        ]

        return base_page(
            *components,
            title='Добавить конфигурацию',
        )

    def get_project_config_info(self, project_id: int) -> ProjectConfigGetDTO:
        project_conf = requests.get(url=BackendServiceConfig.get_project_config_url(project_id)).json()

        project_conf = ProjectConfigGetDTO(**project_conf)

        return project_conf

    def get_project_config_view(self, project_id: int) -> list[AnyComponent]:
        project_conf = self.get_project_config_info(project_id)

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

    def add_project_config(self, conf_id: int, form: Annotated[ProjectScanConfAddForm, fastui_form(ProjectScanConfAddForm)]):

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

        response = requests.post(
            url=BackendServiceConfig.add_project_config_url(),
            headers=headers,
            json=data.model_dump(mode='json')
        )
        validated_response = AddItemResponseDTO.model_validate(response.json())

        return [c.FireEvent(event=GoToEvent(url=FrontendServiceConfig.get_scan_project_config(validated_response.created_item_id)))]

    def add_scan_project_view(self, conf_id: int) -> list[AnyComponent]:
        components = [
            c.Heading(text='Добавить конфигурацию проекта', level=2),
            c.ModelForm(
                model=ProjectScanConfAddForm,
                display_mode='page',
                submit_url=FrontendServiceConfig.submit_project_config_url(conf_id),
            )
        ]

        return base_page(
            *components,
            title='Добавить конфигурацию проекта',
        )

    def start_config_scanner(self, conf_id: int) -> list[AnyComponent]:
        headers = {
            'accept': 'application/json',
        }

        response = requests.post(
            url=BackendServiceConfig.run_scanner_url(conf_id),
            headers=headers,
        )

        validated_response = AddItemResponseDTO.model_validate(response.json())

        return [c.FireEvent(event=BackEvent())]
