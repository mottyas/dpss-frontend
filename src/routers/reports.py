"""Модуль маршрутов отчетов"""

from fastapi import APIRouter, Depends
from fastui import FastUI, AnyComponent
from services.reports import ReportsService


report_router = APIRouter(prefix="/api/reports")


@report_router.get('/', response_model=FastUI, response_model_exclude_none=True)
def get_reports(page: int = 1, page_size: int = 10, report_service: ReportsService = Depends()) -> list[AnyComponent]:
    """Получение списка отчетов"""

    return report_service.get_reports_view(page, page_size)


@report_router.get('/{report_id}', response_model=FastUI, response_model_exclude_none=True)
def get_report(report_id: int, page: int = 1, page_size: int = 10, report_service: ReportsService = Depends()) -> list[AnyComponent]:
    """Получение отчета по идентификатору"""

    return report_service.get_report_view(report_id, page, page_size)
