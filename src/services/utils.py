"""Модуль вспомогательных функций"""

from fastui import components as c
from fastui.events import GoToEvent

from schemas.models import AffectedGetDTO


def gen_link(url: str, text: str | int | None = None) -> c.Link:
    """
    Функция генерации простой GoTo ссылки

    :param url: URL адрес ссылки
    :param text: Текст ссылки
    :return: Объект ссылки Fast-UI
    """

    if not text:
        text = url

    return c.Link(components=[c.Text(text=str(text))], on_click=GoToEvent(url=url))

def fix_date_str(raw_date: str = '10_06_2025_14_14_07') -> str:
    fixed_date = '.'.join(raw_date.split('_')[:3]) + ' ' + ':'.join(raw_date.split('_')[3:])
    return fixed_date

def count_vulnerable_interval(affected: AffectedGetDTO) -> str:
    start = '[' if affected.start_condition == 'gte' else '('
    end = ']' if affected.end_condition == 'lte' else ')'
    return f'{start}{affected.start_value}, {affected.end_value}{end}'
