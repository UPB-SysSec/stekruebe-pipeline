from dataclasses import dataclass


@dataclass
class Fingerprint:
    pass

    @staticmethod
    def from_zgrab_http(zgrabHttpOutput):
        return Fingerprint()
