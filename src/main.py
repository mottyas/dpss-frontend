"""Главный модуль сервиса"""

import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastui import FastUI, AnyComponent, prebuilt_html, components as c
from fastui.events import BackEvent

from const import INDEX_PAGE_TEXT
from routers import routers
from ui.base import base_page


app = FastAPI()

# Подключение маршрутов.
for router in routers:
    app.include_router(router)


@app.get('/api/', response_model=FastUI, response_model_exclude_none=True)
def get_index() -> list[AnyComponent]:
    components = [
        c.Markdown(
            text=INDEX_PAGE_TEXT,
        ),
    ]

    return base_page(*components)


@app.get('/{path:path}')
async def html_landing() -> HTMLResponse:
    """Simple HTML page which serves the React app, comes last as it matches all paths."""
    return HTMLResponse(prebuilt_html(title='DPSS Service'))


if __name__ == '__main__':
    uvicorn.run(
        app='main:app',
        host='0.0.0.0',
        port=8000,
        reload=True,
        log_level='debug',
        workers=1,
    )
