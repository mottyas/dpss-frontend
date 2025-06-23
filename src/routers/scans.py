"""Модуль маршрутов сканирований"""

from typing import Annotated

from fastapi import APIRouter, Depends
from fastui import FastUI, AnyComponent, components as c
from fastui.forms import fastui_form

from services.scans import ScannerService
from schemas.forms import (
    ScanConfAddForm,
    ProjectScanConfAddForm,
    RunScannerForm,
)


scan_router = APIRouter(prefix="/api/scan")


@scan_router.get('/configs', response_model=FastUI, response_model_exclude_none=True)
def get_scan_configs(page: int = 1, page_size: int = 7, scanner_service: ScannerService = Depends()) -> list[AnyComponent]:
    return scanner_service.get_scan_configs_view(page, page_size)


@scan_router.get('/configs/add', response_model=FastUI, response_model_exclude_none=True)
def add_new_scan_config(scanner_service: ScannerService = Depends()) -> list[AnyComponent]:
    return scanner_service.add_scan_config_view()


@scan_router.get('/projects/{project_id}', response_model=FastUI, response_model_exclude_none=True)
def get_project_config(project_id: int, scanner_service: ScannerService = Depends()) -> list[AnyComponent]:
    return scanner_service.get_project_config_view(project_id)


@scan_router.get('/configs/{conf_id}', response_model=FastUI, response_model_exclude_none=True)
def get_scan_config(conf_id: int, page: int = 1, page_size: int = 7, scanner_service: ScannerService = Depends()) -> list[AnyComponent]:
    """Получение отчета по идентификатору"""

    return scanner_service.get_scan_config_view(conf_id, page, page_size)


@scan_router.post('/run/{conf_id}', response_model=FastUI, response_model_exclude_none=True)
def run_scanner(conf_id: int, form: Annotated[RunScannerForm, fastui_form(RunScannerForm)], scanner_service: ScannerService = Depends()) -> list[AnyComponent]:
    scanner_service.start_config_scanner(conf_id)

@scan_router.post('/configs/{conf_id}/add_project', response_model=FastUI, response_model_exclude_none=True)
def add_new_scan_project_config(conf_id: int, form: Annotated[ProjectScanConfAddForm, fastui_form(ProjectScanConfAddForm)], scanner_service: ScannerService = Depends()) -> list[AnyComponent]:
    return scanner_service.add_project_config(conf_id, form)


@scan_router.get('/configs/{conf_id}/add_project', response_model=FastUI, response_model_exclude_none=True)
def add_new_scan_project_config_form(conf_id: int, scanner_service: ScannerService = Depends()) -> list[AnyComponent]:
    return scanner_service.add_scan_project_view(conf_id)

@scan_router.post('/configs/add', response_model=FastUI, response_model_exclude_none=True)
def add_new_scan_config(form: Annotated[ScanConfAddForm, fastui_form(ScanConfAddForm)], scanner_service: ScannerService = Depends()) -> list[c.FireEvent]:
    """Добавление новой конфигурации сканирования"""

    return scanner_service.add_scan_config(form)
