from dataclasses import dataclass


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


mongodb_creds = _Credentials.from_file("mongo/credentials")
neo4j_creds = _Credentials.from_file("neo4j/credentials")
