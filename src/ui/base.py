"""Модуль с базовыми UI элементами"""

from fastui import AnyComponent, components as c
from fastui.events import GoToEvent, BackEvent


BASE_NAVBAR = c.Navbar(
    title='DPSS UI',
    title_event=GoToEvent(url='/'),
    start_links=[
        c.Link(
            components=[c.Text(text='Отчеты')], on_click=GoToEvent(url='/reports/')
        ),
        c.Link(
            components=[c.Text(text='Конфигурации сканирования')], on_click=GoToEvent(url='/scan/configs')
        ),
        c.Link(
            components=[c.Text(text='База уязвимостей')], on_click=GoToEvent(url='/vulners/')
        ),
    ],
    end_links = [
        c.Link(
            components=[c.Text(text='Авторизация')], on_click=BackEvent()
        ),
        c.Link(
            components=[c.Text(text='Справка')], on_click=BackEvent()
        ),
    ],
)

def base_navbar() -> c.Navbar:
    return c.Navbar(
        title='DPSS UI',
        title_event=GoToEvent(url='/'),
        start_links=[
            c.Link(
                components=[c.Text(text='База уязвимостей')],
                on_click=GoToEvent(url='/vulners/')
            ),
            c.Link(
                components=[c.Text(text='Конфигурации сканирования')],
                on_click=GoToEvent(url='/scan/configs')
            ),
            c.Link(
                components=[c.Text(text='Отчеты')],
                on_click=GoToEvent(url='/reports/')
            ),
        ],
        end_links = [
            c.Link(
                components=[c.Text(text='Авторизация')],
                on_click=BackEvent()
            ),
            c.Link(
                components=[c.Text(text='Справка')],
                on_click=BackEvent()
            ),
        ],
    )

def base_footer() -> c.Footer:
    return c.Footer(
        extra_text='DPSS UI',
        links=[
            c.Link(
                components=[c.Text(text='Github')],
                on_click=GoToEvent(url='https://github.com/pydantic/FastUI')
            ),
            c.Link(
                components=[c.Text(text='PyPI')],
                on_click=GoToEvent(url='https://pypi.org/project/fastui/')
            ),
            c.Link(
                components=[c.Text(text='NPM')],
                on_click=GoToEvent(url='https://www.npmjs.com/org/pydantic/')
            ),
        ],
    )


def base_page(*components: AnyComponent, title: str | None = None) -> list[AnyComponent]:
    return [
        c.PageTitle(text=f'DPSS UI — {title}' if title else 'DPSS UI'),
        base_navbar(),
        c.Page(
            components=[
                *((c.Heading(text=title),) if title else (c.Heading(text='DPSS UI'),)),
                c.Link(
                    components=[c.Text(text='Вернуться назад')], on_click=BackEvent()
                ),
                *components,
            ],
        ),
        base_footer(),
    ]

def gen_ui_link(url: str, text: str | int | None = None) -> c.Link:
    """
    Функция генерации простой GoTo ссылки

    :param url: URL адрес ссылки
    :param text: Текст ссылки
    :return: Объект ссылки Fast-UI
    """

    if not text:
        text = url

    return c.Link(components=[c.Text(text=str(text))], on_click=GoToEvent(url=url))
