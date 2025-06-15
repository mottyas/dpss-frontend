
from fastui import components as c
from fastui.events import GoToEvent


def gen_go_to_link(url: str, text: str | None = None) -> c.Link:
    """
    Функция генерации просто GoTo ссылки

    :param url: URL адрес ссылки
    :param text: Текст ссылки
    :return: Объект ссылки Fast-UI
    """

    if not text:
        text = url

    return c.Link(components=[c.Text(text=text)], on_click=GoToEvent(url=url))
