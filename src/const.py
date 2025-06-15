from fastui import components as c
from fastui.events import GoToEvent, BackEvent


BASE_NAVBAR = c.Navbar(
    title='DPSS UI',
    title_event=GoToEvent(url='/'),
    start_links=[
        c.Link(
            components=[c.Text(text='Отчеты')], on_click=GoToEvent(url='/reports')
        ),
        # c.Link(
        #     components=[c.Text(text='Вернуться назад')], on_click=BackEvent()
        # ),
        c.Link(
            components=[c.Text(text='Конфигурации сканирования')], on_click=GoToEvent(url='/scan/configs')
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
