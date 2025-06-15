

from pydantic import BaseModel


class Vulner(BaseModel):
    id: int
    identifier: str
    description: str
    affected_components: str
    severity: str


class Report(BaseModel):
    id: int
    vulners: list[Vulner]
    description: str
    name: str


class ScanConf(BaseModel):
    id: int
    name: str
    host: str
    user: str
    password: str
    description: str = ''


ScanConfTableData = [
    ScanConf(id=1, name='DevOpsScanConfig', host='127.0.0.1', user='somedevuser', password='some1password'),
    ScanConf(id=2, name='BackEndScanConfig', host='192.186.0.1', user='somebackuser', password='some2password'),
    ScanConf(id=3, name='FrontEndScanConfig', host='172.129.0.1', user='somefrontuser', password='some3password'),
]

VulnerTableData = (
    Vulner(id=1, identifier='CVE-1', description='Some description of CVE-1', affected_components='some-python-pkg_1.1.1, some-another-package_2.2.2', severity='low'),
    Vulner(id=2, identifier='CVE-2', description='Some description of CVE-1', affected_components='some-python-pkg_1.1.1, some-another-package_2.2.2', severity='high'),
    Vulner(id=3, identifier='CVE-3', description='Some description of CVE-1', affected_components='some-python-pkg_1.1.1, some-another-package_2.2.2', severity='critical'),
    Vulner(id=4, identifier='CVE-4', description='Some description of CVE-4', affected_components='some-python-pkg_1.1.1, some-another-package_2.2.2', severity='medium'),
)


ReportTableData = (
    Report(id=1, vulners=list(VulnerTableData), description='Some interesting report for devops team', name='ReportDevOps'),
    Report(id=2, vulners=list(VulnerTableData), description='Some interesting report for backend team', name='ReportBack'),
    Report(id=3, vulners=list(VulnerTableData), description='Some interesting report for frontend team', name='ReportFront'),
)
