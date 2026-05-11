from pydantic import BaseModel
from typing import List, Optional
from enum import Enum

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

class Package(BaseModel):
    name: str
    version: str
    ecosystem: str
    purl: Optional[str] = None

class Vulnerability(BaseModel):
    id: str
    summary: Optional[str] = None
    severity: Severity = Severity.UNKNOWN
    cvss_score: Optional[float] = None
    aliases: List[str] = []

class SbomReport(BaseModel):
    project_name: str
    packages: List[Package]
    vulnerabilities: List[Vulnerability] = []
    total_packages: int = 0
    critical_count: int = 0
    high_count: int = 0
