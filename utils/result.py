from dataclasses import dataclass
from enum import Enum
from . import json_serialization as json


@dataclass(frozen=True)
class Connectable:
    ip: str
    port: int

    def __str__(self):
        return f"{self.ip}:{self.port}"

    def __repr__(self) -> str:
        return f"<Connectable {self.ip!r}:{self.port!r}>"


class ScanVersion(Enum):
    TLS1_0 = "0x0301"
    TLS1_1 = "0x0302"
    TLS1_2 = "0x0303"
    TLS1_3 = "0x0304"
    PRE_1_3 = "_custom_"

    @classmethod
    def from_name(cls, name: str):
        # TLSv1.3 -> TLS1_3
        return cls[name.replace("v", "").replace(".", "_")]


class Zgrab2ResumptionResultStatus(Enum):
    PENDING = "pending"
    INITIAL_RAN = "initial_ran"
    INITIAL_PARSED = "initial_parsed"
    INITIAL_NO_TICKET = "initial_no_ticket"
    INITIAL_NO_VERSION = "initial_no_version"
    RESUMPTION_RAN = "resumption_ran"
    RESUMPTION_PARSED = "resumption_parsed"
    SUCCESS = "success"


@dataclass
class Zgrab2ResumptionResult:
    domain_from: str
    addr_from: Connectable
    version: ScanVersion
    target_addrs: list[Connectable]
    status: Zgrab2ResumptionResultStatus
    error: str = None
    initial: dict = None
    initial_exitcode: int = None
    initial_status_line: dict = None
    redirect: list[dict] = None
    redirect_exitcode: int = None
    redirect_status_line: dict = None

    def to_dict(self):
        # dirty way to convert to serializable for DB
        return json.loads(json.dumps(self))
