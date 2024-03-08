from pymongo import MongoClient
from enum import Enum
from dataclasses import dataclass
from typing import Union, Optional
from utils.credentials import mongodb_creds
from utils.result import Zgrab2ResumptionResult


class Response:
    def __init__(self, zgrabHttpOutput):
        self._zgrabHttpOutput = zgrabHttpOutput
        self._ip = zgrabHttpOutput["ip"]
        if zgrabHttpOutput["data"]["http"].get("error", False):
            self._response = {"status_code": -1, "headers": {}}
            self._handshake_log = {}
        else:
            self._response = zgrabHttpOutput["data"]["http"]["result"]["response"]
            self._handshake_log = self._response["request"]["tls_log"]["handshake_log"]
        self.resumed = "server_certificates" not in self._handshake_log
        self.status_code = self._response["status_code"]
        self.body_sha256 = self._response.get("body_sha256", None)
        self.content_title = self._response.get("content_title", None)
        self.location = self._response["headers"].get("location", [])
        assert len(self.location) < 2
        self.location = self.location[0] if self.location else None

        # filter location
        if self.location and self.location.startswith("/sttc/px/captcha-v2/index.html?url=Lz8"):
            self.location = "/sttc/px/captcha-v2/index.html?url=Lz8"

    def __str__(self) -> str:
        sha_format = "{:.6s}" if self.body_sha256 else "None"
        return f"Response(status_code={self.status_code!r}, body_sha256={sha_format}, content_title={self.content_title!r}, location={self.location!r})"

    def __repr__(self) -> str:
        return f"Response(status_code={self.status_code!r}, body_sha256={self.body_sha256!r}, content_title={self.content_title!r}, location={self.location!r})"


class ResumptionClassificationTyp(Enum):
    NOT_APPLICABLE = 0
    SAFE = 1
    UNSAFE = 2

    @staticmethod
    def from_bool_is_safe(is_safe):
        return ResumptionClassificationTyp.SAFE if is_safe else ResumptionClassificationTyp.UNSAFE

    @property
    def is_safe(self):
        return self.value <= ResumptionClassificationTyp.SAFE.value


@dataclass
class ResumptionClassification:
    classification: ResumptionClassificationTyp
    reason: str
    value_initial: Optional[str]
    value_redirect: Optional[str]

    def __init__(
        self,
        is_safe: Union[ResumptionClassificationTyp, bool],
        reason: str,
        reason_initial: Optional[str] = None,
        reason_redirect: Optional[str] = None,
    ):
        if isinstance(is_safe, bool):
            self.classification = ResumptionClassificationTyp.from_bool_is_safe(is_safe)
        else:
            self.classification = is_safe
        self.reason = reason
        self.value_initial = reason_initial
        self.value_redirect = reason_redirect

    @property
    def is_safe(self):
        return self.classification.is_safe

    @staticmethod
    def safe(reason):
        return ResumptionClassification(ResumptionClassificationTyp.SAFE, reason)

    @staticmethod
    def not_applicable(reason):
        return ResumptionClassification(ResumptionClassificationTyp.NOT_APPLICABLE, reason)

    @staticmethod
    def unsafe(reason, a=None, b=None):
        return ResumptionClassification(ResumptionClassificationTyp.UNSAFE, reason, a, b)

    @staticmethod
    def assert_equal(a, b, reason):
        return ResumptionClassification(a == b, reason, a, b)


def classify_resumption(initial: Response, resumption: Response):
    # TODO maybe classify multiple redirects at once
    if not resumption.resumed:
        return ResumptionClassification.safe("no resumption")
    # initial was error - ignore
    if initial.status_code < 0 or resumption.status_code < 0:
        return ResumptionClassification.not_applicable("initial or redirect was complete error")
    if initial.status_code > 400:
        return ResumptionClassification.not_applicable("initial was error")

    if resumption.status_code == 403:
        # assume the 403 is ok
        return ResumptionClassification.safe("resumption got 403")
    if resumption.status_code == 421:
        return ResumptionClassification.safe("resumption got 421 - redirection was detected")
    if resumption.status_code == 429:
        return ResumptionClassification.not_applicable("they blocked us :(")

    if initial.status_code in range(300, 400):
        assert initial.location
        if resumption.status_code in range(300, 400):
            assert resumption.location
            return ResumptionClassification.assert_equal(initial.location, resumption.location, "location")
        return ResumptionClassification.unsafe(
            "initial was redirect, resumption was not", initial.status_code, resumption.status_code
        )

    if initial.body_sha256 is not None and initial.body_sha256 == resumption.body_sha256:
        # same content
        return ResumptionClassification.safe("body sha256")
    if initial.content_title is not None:
        # same title -> probably same content
        return ResumptionClassification.assert_equal(initial.content_title, resumption.content_title, "title")

    # TODO decide here...
    return ResumptionClassification.unsafe("unsure")


problematic_domains = set()


def analyze_collection(collection):
    print("#" * 80)
    for doc in collection.find({"status": "SUCCESS"}):
        del doc["_id"]
        result = Zgrab2ResumptionResult(**doc)
        initial = Response(result.initial)
        found = False
        for redirected in map(Response, result.redirect):
            classification = classify_resumption(initial, redirected)
            if not classification.is_safe:
                if found:
                    print("-" * 80)
                found = True
                print("We got a connection to a different server without authentication")
                print(
                    f"Ticket from {result.domain_from} at {initial._ip} -> {redirected._ip} in {result.version} | Detected with {classification.reason}"
                )
                print("Value Initial   :", repr(classification.value_initial))
                print("Value Resumption:", repr(classification.value_redirect))
                print("Initial   :", initial)
                print("Resumption:", redirected)
                # print(
                #     f'create_test("scan", Remote("{result.domain_from}", "{initial._ip}"), Remote(None, "{redirected._ip}"), create_reversed=False)'
                # )
                print(
                    f"""
        host_ticket = Remote("{result.domain_from}", "{initial._ip}")
        host_resumption = Remote("{redirected._ip}")""".strip(
                        "\n"
                    )
                )
                if classification.reason == "unsure":
                    if result.domain_from not in problematic_domains:
                        print("")
                    problematic_domains.add(result.domain_from)

        if found:
            print("#" * 80)


def main():
    mongo_url = f"mongodb://{mongodb_creds.as_str()}@127.0.0.1:27017/?authSource=admin&readPreference=primary&directConnection=true&ssl=true"
    print(f"Connecting to {mongo_url=}")
    mongo_driver = MongoClient(mongo_url, tlsAllowInvalidCertificates=True)
    mongo_driver.server_info()
    print("Connected to MongoDB")
    db = mongo_driver["steckruebe"]
    collection_name = "ticket_redirection_2024-03-06 17:11:59.868281"
    if collection_name:
        analyze_collection(db[collection_name])
    else:
        for collection_name in db.list_collection_names():
            print(f"Collection: {collection_name}")
            analyze_collection(db[collection_name])


if __name__ == "__main__":
    main()
