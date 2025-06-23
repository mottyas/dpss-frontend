"""Модуль настроек конфигурации сервисов"""

import os


class BackendServiceConfig:
    """Класс настроек бэкенд сервиса"""

    protocol = os.getenv('BACKEND_SERVICE_PROTOCOL', 'http')
    host = os.getenv('BACKEND_SERVICE_HOST', 'localhost')
    port = os.getenv('BACKEND_SERVICE_PORT', 5000)
    api_version = os.getenv('API_VERSION', 'v1')

    @classmethod
    def service_url(cls, handler_path: str) -> str:
        return f'{cls.protocol}://{cls.host}:{cls.port}/{cls.api_version}/{handler_path}'

    @classmethod
    def get_reports_url(cls):
        return cls.service_url('scan/reports')

    @classmethod
    def get_report_url(cls, item_id: int):
        return cls.service_url(f'scan/reports/id/{item_id}')

    @classmethod
    def get_vulners_url(cls):
        return cls.service_url('scan/vulners')

    @classmethod
    def get_vulner_url(cls, item_id: str):
        return cls.service_url(f'scan/vulners/{item_id}')

    @classmethod
    def get_config_url(cls, item_id: int):
        return cls.service_url(f'scan/confs/id/{item_id}')

    @classmethod
    def get_configs_url(cls):
        return cls.service_url('scan/confs/all')

    @classmethod
    def add_configs_url(cls):
        return cls.service_url('scan/confs')

    @classmethod
    def add_project_config_url(cls):
        return cls.service_url('scan/projects')

    @classmethod
    def get_project_config_url(cls, item_id: int):
        return cls.service_url(f'scan/projects/{item_id}')

    @classmethod
    def run_scanner_url(cls, item_id: int):
        return cls.service_url(f'scan/run/{item_id}')


class FrontendServiceConfig:
    """Класс настроек фронтенд сервиса"""

    @classmethod
    def get_vulner(cls, item_id: str):
        return f'/vulners/{item_id}'

    @classmethod
    def get_vulners(cls):
        return f'/vulners/'

    @classmethod
    def get_report(cls, item_id: int):
        return f'/reports/{item_id}'

    @classmethod
    def get_reports(cls):
        return '/reports/'

    @classmethod
    def get_scan_configs(cls):
        return f'/scan/configs/'

    @classmethod
    def get_scan_config(cls, item_id: int):
        return f'/scan/configs/{item_id}'

    @classmethod
    def get_scan_project_config(cls, item_id: int):
        return f'/scan/projects/{item_id}'

    @classmethod
    def get_scan_project(cls, item_id: int):
        return f'/scan/projects/{item_id}'

    @classmethod
    def add_project_config_url(cls, config_id: int):
        return f'/scan/configs/{config_id}/add_project'

    @classmethod
    def submit_project_config_url(cls, config_id: int):
        return f'/api/scan/configs/{config_id}/add_project'

    @classmethod
    def submit_scanner_run_url(cls, config_id: int):
        return f'/api/scan/run/{config_id}'

    @classmethod
    def submit_add_config_url(cls):
        return f'/api/scan/configs/add'

    @classmethod
    def submit_add_project_config_url(cls, conf_id: int):
        return f'/api/scan/configs/{conf_id}/add_project'
