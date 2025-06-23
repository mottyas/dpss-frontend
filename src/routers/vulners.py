"""Модуль маршрутов базы уязвимостей"""


from fastapi import APIRouter
from fastapi.params import Depends
from fastui import FastUI, AnyComponent

from services.vulners import VulnersService


vulners_router = APIRouter(prefix="/api/vulners")


@vulners_router.get('/', response_model=FastUI, response_model_exclude_none=True)
def get_vulners(page: int = 1, page_size: int = 7, vulner_service: VulnersService = Depends()) -> list[AnyComponent]:
    return vulner_service.get_view_vulners(page, page_size)


@vulners_router.get('/{item_id}', response_model=FastUI, response_model_exclude_none=True)
def get_vulner_data(item_id: str, vulner_service: VulnersService = Depends()) -> list[AnyComponent]:
    return vulner_service.get_view_vulner(item_id)
