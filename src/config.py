import os


class BackendServiceConfig:
    """Класс настроек бэкенд сервиса"""

    protocol = os.getenv('BACKEND_SERVICE_PROTOCOL', 'http')
    host = os.getenv('BACKEND_SERVICE_HOST', 'localhost')
    port = os.getenv('BACKEND_SERVICE_PORT', 8001)
    api_version = os.getenv('API_VERSION', 'v1')

    @classmethod
    def service_url(cls, handler_path: str) -> str:
        return f'{cls.protocol}://{cls.host}:{cls.port}/{cls.api_version}/{handler_path}'
