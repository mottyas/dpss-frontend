
from enum import Enum
from pydantic import BaseModel, Field

class ScanConfAddForm(BaseModel):
    name: str
    host: str
    user: str
    password: str
    description: str = ''
    port: str = '22'

class ProjectTypes(Enum):
    python = 'python'
    golang = 'golang'
    javascript = 'javascript'

class ProjectScanConfAddForm(BaseModel):
    name: str
    type: ProjectTypes
    dir_path: str
    description: str = ''

class RunScannerForm(BaseModel):
    pass
    # config_id: int
