from dataclasses import dataclass
from pathlib import Path


@dataclass
class _Credentials:
    username: str
    password: str

    @staticmethod
    def from_file(filename: str):
        with open(filename) as f:
            return _Credentials(*f.read().strip().split(":"))

    def as_tuple(self):
        return self.username, self.password

    def as_str(self):
        return f"{self.username}:{self.password}"


_base_dir = Path(__file__).parent.parent
mongodb_creds = _Credentials.from_file(_base_dir / "mongo/credentials")
neo4j_creds = _Credentials.from_file(_base_dir / "neo4j/credentials")
