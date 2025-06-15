

from pydantic import BaseModel, Field

class ScanConfAddForm(BaseModel):
    name: str
    host: str
    user: str
    password: str
    description: str = ''
