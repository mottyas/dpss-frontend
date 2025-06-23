from routers.reports import report_router
from routers.vulners import vulners_router
from routers.scans import scan_router

routers = [
    report_router,
    vulners_router,
    scan_router,
]
