import subprocess
import csv
import logging as logging
import sys
import time
from dataclasses import dataclass
from enum import Enum, StrEnum
from multiprocessing.pool import Pool as ProcessPool
from multiprocessing.pool import ThreadPool
from pprint import pformat, pprint
from typing import Optional, Union
from urllib.parse import urlparse

import utils.json_serialization as json
from neo4j import Driver as Neo4jDriver
from pymongo.collection import Collection
from utils.db import (
    connect_mongo,
    get_most_recent_collection_name,
)
from utils.misc import catch_exceptions
from utils.result import Zgrab2ResumptionResult
from utils.result import ScanVersion
from pathlib import Path
from tqdm import tqdm

LOGGER = logging.getLogger(__name__)

_NEO4J_PATH = Path(__file__).parent / "neo4j"
_NEO4J_PATH_IMPORT = _NEO4J_PATH / "import"


class ScanContext:
    neo4j: Neo4jDriver = None
    mongo_collection: Collection = None
    resumption_collection: Collection = None

    @staticmethod
    def initialize(mongo_collection_name=None, *, verify_connectivity=True):

        # ScanContext.neo4j = connect_neo4j(verify_connectivity=verify_connectivity)
        mongodb = connect_mongo(verify_connectivity=verify_connectivity)
        database = mongodb["steckruebe"]
        if not mongo_collection_name:
            mongo_collection_name = get_most_recent_collection_name(database, "ticket_redirection_")
            LOGGER.info(f"Using most recent collection: {mongo_collection_name}")
        if not mongo_collection_name:
            raise ValueError("Could not determine most recent collection")
        ScanContext.mongo_collection = database[mongo_collection_name]
        # resumption collection is used for post processing the original collection
        ScanContext.resumption_collection = database[f"{mongo_collection_name}_resumptions"]


class Response:
    def __init__(self, zgrabHttpOutput):
        self._zgrabHttpOutput = zgrabHttpOutput
        self._ip = zgrabHttpOutput["ip"]
        if zgrabHttpOutput["data"]["http"].get("error", False):
            self._response = {}
            self._handshake_log = {}
        else:
            self._response = zgrabHttpOutput["data"]["http"]["result"]["response"]
            self._handshake_log = self._response["request"]["tls_log"]["handshake_log"]
        self.resumed = "server_certificates" not in self._handshake_log
        if self.resumed:
            self.certificate = None
            self.parsed_certificate = None
        else:
            self.certificate = self._handshake_log["server_certificates"]["certificate"]["raw"]
            self.parsed_certificate = self._handshake_log["server_certificates"]["certificate"].get("parsed")
        self.status_code = self._response.get("status_code", -1)
        self.body_sha256 = self._response.get("body_sha256", None)
        self.body = self._response.get("body", None)
        self.body_len = self._response.get("body_len", None)
        self.content_title = self._response.get("content_title", None)
        self.content_length = self._response.get("content_length", None)
        self.body_boxp = self._response.get("body_boxp", None)
        self.body_botp = self._response.get("body_botp", None)
        self.location = self._response.get("headers", {}).get("location", [])
        if len(self.location) > 1:
            if len(set(self.location)) == 1:
                LOGGER.info(
                    f"Same location was specified multiple times, reducing to one: {self.location} for {self._ip}"
                )
                self.location = [self.location[0]]
            else:
                LOGGER.warning(f"Multiple distinct locations: {self.location} for {self._ip}")

    def __str__(self) -> str:
        sha_format = f"{self.body_sha256:.6s}" if self.body_sha256 else "None"
        return f"Response(status_code={self.status_code!r}, body_sha256={sha_format}, content_title={self.content_title!r:.50}, content_length={self.content_length!r}, body_len={self.body_len!r}, location={self.location!r})"

    def __repr__(self) -> str:
        return f"Response(status_code={self.status_code!r}, body_sha256={self.body_sha256!r}, content_title={self.content_title!r:.50}, content_length={self.content_length!r}, body_len={self.body_len!r}, location={self.location!r})"


@dataclass
class AnalyzedZgrab2ResumptionResult(Zgrab2ResumptionResult):
    """Convinience Class; transforms initial and redirect into response objects rather than dicts"""

    initial: Response = None
    redirect: list[Response] = None

    def __post_init__(self):
        if self.initial:
            self.initial = Response(self.initial)
        if self.redirect:
            self.redirect = [Response(r) for r in self.redirect]


# region Classification


class ResumptionClassificationType(Enum):
    NOT_APPLICABLE = 0
    SAFE = 1
    UNSAFE = 2
    LOOK_AT_METRICS = 3

    @staticmethod
    def from_bool_is_safe(is_safe):
        return ResumptionClassificationType.SAFE if is_safe else ResumptionClassificationType.UNSAFE

    @property
    def is_safe(self):
        return self.value <= ResumptionClassificationType.SAFE.value


@dataclass
class ResumptionClassification:
    classification: ResumptionClassificationType
    reason: str
    value_initial: Optional[str]
    value_redirect: Optional[str]

    def __init__(
        self,
        is_safe: Union[ResumptionClassificationType, bool],
        reason: str,
        reason_initial: Optional[str] = None,
        reason_redirect: Optional[str] = None,
    ):
        if isinstance(is_safe, bool):
            self.classification = ResumptionClassificationType.from_bool_is_safe(is_safe)
        else:
            self.classification = is_safe
        self.reason = reason
        self.value_initial = reason_initial
        self.value_redirect = reason_redirect

    @property
    def is_safe(self):
        return self.classification.is_safe

    @staticmethod
    def safe(reason, a=None, b=None):
        return ResumptionClassification(ResumptionClassificationType.SAFE, reason, a, b)

    @staticmethod
    def not_applicable(reason, a=None, b=None):
        return ResumptionClassification(ResumptionClassificationType.NOT_APPLICABLE, reason, a, b)

    @staticmethod
    def look_at_metrics():
        return ResumptionClassification(ResumptionClassificationType.LOOK_AT_METRICS, "need to classify using metrics")

    @staticmethod
    def unsafe(reason, a=None, b=None):
        return ResumptionClassification(ResumptionClassificationType.UNSAFE, reason, a, b)

    @staticmethod
    def assert_equal(a, b, reason):
        return ResumptionClassification(a == b, reason, a, b)

    @staticmethod
    def assert_true(truthy, a, b, reason):
        return ResumptionClassification(bool(truthy), reason, a, b)

    def to_dict(self):
        # dirty way to convert to serializable for DB
        return json.loads(json.dumps(self))


def are_same_origin(url1, url2):
    p1 = urlparse(url1)
    p2 = urlparse(url2)
    return p1.scheme == p2.scheme and p1.port == p2.port and p1.hostname == p2.hostname


def classify_resumption(initial: Response, resumption: Response, domain_from: str):
    # TODO maybe classify multiple resumptions at once
    if not resumption.resumed:
        return ResumptionClassification.safe("no resumption")
    # initial was error - ignore
    if initial.status_code < 0:
        return ResumptionClassification.not_applicable("initial was complete error")
    if resumption.status_code < 0:
        return ResumptionClassification.not_applicable("redirect was complete error")
    if initial.status_code > 400:
        return ResumptionClassification.not_applicable("initial was error")

    if resumption.status_code == 403:
        return ResumptionClassification.not_applicable("resumption got 403")
    if resumption.status_code == 421:
        return ResumptionClassification.safe("resumption got 421 - redirection was detected")
    if resumption.status_code == 429:
        return ResumptionClassification.not_applicable("resumption got 429 - they blocked us :(")
    if resumption.status_code == 502:
        return ResumptionClassification.not_applicable("resumption got 502 - not routed")
    if resumption.status_code == 525:
        # 525 SSL handshake failed
        # (via https???)
        return ResumptionClassification.not_applicable("resumption got 525 - failed on HTTP layer")

    # initially we were redirected ...
    if initial.status_code in range(300, 400):
        if not initial.location:
            return ResumptionClassification.not_applicable("initial redirection had no location set")
        if resumption.status_code in range(300, 400):
            if not resumption.location:
                return ResumptionClassification.not_applicable("resumption redirection had no location set")
            # ... on resumption as well - was the location the same?
            if initial.location == resumption.location:
                return ResumptionClassification.safe("location", initial.location, resumption.location)
            if len(initial.location) > 1 or len(resumption.location) > 1:
                return ResumptionClassification.not_applicable(
                    "multiple locations specified in one response", initial.location, resumption.location
                )
            # or at least same origin?
            return ResumptionClassification.assert_true(
                are_same_origin(initial.location[0], resumption.location[0]),
                initial.location[0],
                resumption.location[0],
                "location SOP",
            )
        # ... but not on resumption - which means the server is handling us differently
        return ResumptionClassification.unsafe(
            "initial was redirect, resumption was not",
            initial.status_code,
            resumption.status_code,
        )

    # if resumption 300 and initial 200 check redirect to original
    if resumption.status_code in range(300, 400):
        if not resumption.location:
            return ResumptionClassification.not_applicable("resumption had no location even though 3XX code set")
        if len(resumption.location) > 1:
            return ResumptionClassification.not_applicable(
                "multiple locations specified in one response (initial was no redirect)", resumption.location
            )
        parsed_location = urlparse(resumption.location[0].lower())
        if not parsed_location.hostname and not parsed_location.scheme:
            # relative path -> NA
            return ResumptionClassification.not_applicable("relative redirect on resumption", b=resumption.location[0])

        if parsed_location.netloc == domain_from:
            if parsed_location.scheme == "https":
                return ResumptionClassification.safe("redirect to original (https)", b=resumption.location[0])
            if parsed_location.scheme == "http":
                return ResumptionClassification.safe("redirect to original (http)", b=resumption.location[0])
            if not parsed_location.scheme:
                return ResumptionClassification.safe(
                    "redirect to original (no scheme/implicit https)", b=resumption.location[0]
                )
            return ResumptionClassification.not_applicable(
                "redirect to original (other scheme)", b=resumption.location[0]
            )
        if parsed_location.netloc == "www." + domain_from:
            if parsed_location.scheme == "https":
                return ResumptionClassification.safe("redirect to www.original (https)", b=resumption.location[0])
            if parsed_location.scheme == "http":
                return ResumptionClassification.safe("redirect to www.original (http)", b=resumption.location[0])
            if not parsed_location.scheme:
                return ResumptionClassification.safe(
                    "redirect to www.original (no scheme/implicit https)", b=resumption.location[0]
                )
            return ResumptionClassification.not_applicable(
                "redirect to www.original (other scheme)", b=resumption.location[0]
            )

        return ResumptionClassification.unsafe("redirect to different", None, resumption.location[0])

    if initial.body_sha256 is not None and initial.body_sha256 == resumption.body_sha256:
        # same content
        return ResumptionClassification.safe("body sha256")
    return ResumptionClassification.look_at_metrics()


# endregion Classification

# region Bulkimport

all_node_ids = set()


@dataclass
class HTMLNode:
    _FILENAME = ""
    _HEADER_FILENAME = ""
    # dummy writer
    # FILE = open("/dev/null", "w")

    def __init__(self, doc_id, ip, domain, version, labels="HTML"):
        self.doc_id = doc_id
        self.ip = ip
        self.domain = domain
        self.version = version
        self.labels = labels

    def header():
        return ":ID,doc_id,ip,domain,version,:LABEL"

    def id(self):
        return hash((self.doc_id, self.ip, self.domain, self.version, self.labels))

    def row(self):
        return (
            self.id(),
            self.doc_id,
            self.ip,
            self.domain,
            self.version,
            self.labels,
        )

    @classmethod
    def write_header(cls):
        with open(cls._HEADER_FILENAME, "w") as f:
            f.write(cls.header())


initial_rows = []


class InitialHTMLNode(HTMLNode):
    _FILENAME = _NEO4J_PATH_IMPORT / "initial_html.csv"
    _HEADER_FILENAME = _NEO4J_PATH_IMPORT / "initial_html_header.csv"
    rows = []

    def __init__(self, doc_id, ip, domain, version, cert_fingerprint):
        super().__init__(doc_id, ip, domain, version, labels="HTML;INITIAL_HTML")
        self.cert_fingerprint = cert_fingerprint

    def header():
        return ":ID(Initial-ID),doc_id,ip,domain,version,cert_fingerprint,:LABEL"

    def row(self):
        return (
            self.id(),
            self.doc_id,
            self.ip,
            self.domain,
            self.version,
            self.cert_fingerprint,
            self.labels,
        )

    def write(self):
        all_node_ids.add(self.id())
        initial_rows.append(self.row())
        # try:
        #     self.initial_html_writer.writerow(self.row())
        # except Exception as e:
        #     print(self.row())
        #     raise e


resumption_rows = []


class ResumptionHTMLNode(HTMLNode):
    _FILENAME = _NEO4J_PATH_IMPORT / "resumption_html.csv"
    _HEADER_FILENAME = _NEO4J_PATH_IMPORT / "resumption_html_header.csv"
    # FILE = open(_FILENAME, "w")

    def __init__(self, doc_id, ip, domain, version, redirect_index):
        super().__init__(doc_id, ip, domain, version, labels="HTML;REDIRECT_HTML")
        self.redirect_index = redirect_index

    def id(self):
        return hash((self.doc_id, self.redirect_index, self.ip, self.domain, self.version, self.labels))

    def row(self):
        return (
            self.id(),
            self.doc_id,
            self.redirect_index,
            self.ip,
            self.domain,
            self.version,
            self.labels,
        )

    def header():
        return ":ID(Resumption-ID),doc_id,redirect_index,ip,domain,version,:LABEL"

    # def write(self):
    #     all_node_ids.add(self.id())
    #     resumption_rows.append(self.row())
    # try:
    #     self.resumption_html_writer.writerow(self.row())
    # except Exception as e:
    #     print(self.row())
    #     raise e


edge_rows = []


class Relationship:
    _FILENAME = _NEO4J_PATH_IMPORT / "html_edges.csv"
    _HEADER_FILENAME = _NEO4J_PATH_IMPORT / "html_edges_header.csv"

    def __init__(
        self,
        initial: InitialHTMLNode,
        resumption: ResumptionHTMLNode,
        classification,
        classification_reason,
        classification_value_initial=None,
        classification_value_redirect=None,
    ):
        self.initial = initial
        self.resumption = resumption
        self.classification = classification
        # escape , because it is used as delimiter
        self.classification_reason = classification_reason.replace(",", ";")
        # self.edge_writer = edge_writer
        self.classification_value_initial = (
            str(classification_value_initial).replace(",", ";") if classification_value_initial else None
        )
        self.classification_value_redirect = (
            str(classification_value_redirect).replace(",", ";") if classification_value_initial else None
        )

    def header():
        return ":START_ID(Initial-ID),:END_ID(Resumption-ID),:TYPE,classification,c_reason,c_value_initial,c_value_redirect"

    def row(self):
        # classification is a string and needs to be quoted for the import tool
        # return (self.initial_id, self.resumption_id, "RESUMED_AT", f'{self.classification}', f'{self.reason}')
        return (
            self.initial.id(),
            self.resumption.id(),
            "RESUMED_AT",
            self.classification,
            self.classification_reason,
            self.classification_value_initial,
            self.classification_value_redirect,
        )

    def write(self):
        assert self.initial.id() in all_node_ids, f"{self.initial.id()} not in {all_node_ids}"
        assert self.resumption.id() in all_node_ids, f"{self.resumption.id()} not in {all_node_ids}"
        edge_rows.append(self.row())
        # try:
        #     self.edge_writer.writerow(self.row())
        # except Exception as e:
        #     print(self.row())
        #     raise e

    @classmethod
    def write_header(cls):
        with open(cls._HEADER_FILENAME, "w") as f:
            f.write(cls.header())


def classify(doc, rows, insert_result: bool = True):
    doc_id = doc["_id"]
    del doc["_id"]
    if "_analyzed" in doc:
        del doc["_analyzed"]
    if "_analysis_errored" in doc:
        del doc["_analysis_errored"]
    initial_rows, resumption_rows, edge_rows = rows
    result = AnalyzedZgrab2ResumptionResult(**doc)
    # insert all successful initial resumption pairs into the resumption collection and assign a unique id
    initial = InitialHTMLNode(
        doc_id=doc_id,
        ip=result.initial._ip,
        domain=result.domain_from,
        version="TLSv1.2" if result.version is ScanVersion.TLS1_2 else "TLSv1.3",
        cert_fingerprint=result.initial.parsed_certificate["fingerprint_sha256"],
    )
    initial_rows.append(initial.row())
    for i, redirect in enumerate(result.redirect):
        classification = classify_resumption(result.initial, redirect, result.domain_from)
        # resumption_doc = {
        #     "initial": result.initial._zgrabHttpOutput,
        #     "initial_id": initial_id,
        #     "redirect": redirect._zgrabHttpOutput,
        #     "resumption_id": ObjectId(),
        #     "classification": classification.classification.name,
        #     "reason": classification.reason,
        # }
        # ScanContext.resumption_collection.insert_one(resumption_doc)
        resumption = ResumptionHTMLNode(
            doc_id=doc_id,
            redirect_index=i,
            ip=redirect._ip,
            domain=result.domain_from,
            version=("TLSv1.2" if result.version is ScanVersion.TLS1_2 else "TLSv1.3"),
        )
        # resumption_writer.writerow(resumption.row())
        resumption_rows.append(resumption.row())
        edge = Relationship(
            initial=initial,
            resumption=resumption,
            classification=classification.classification.name,
            classification_reason=classification.reason,
            classification_value_initial=classification.value_initial,
            classification_value_redirect=classification.value_redirect,
        )
        # edge_writer.writerow(edge.row())
        edge_rows.append(edge.row())


# endregion Bulkimport


def prepare_bulk_import_files(collection_filter=None, LIMIT=None):
    CACHE_KEY = {
        "collection_name": ScanContext.mongo_collection.full_name,
        "collection_filter": collection_filter,
        "LIMIT": LIMIT,
    }
    CACHE_FILE = _NEO4J_PATH_IMPORT / "cache_key.json"

    try:
        with CACHE_FILE.open("r") as f:
            old_cache_key = json.load(f)
    except FileNotFoundError:
        old_cache_key = None

    if old_cache_key == CACHE_KEY:
        LOGGER.info("Cache key matches, skipping bulk import preparation")
        return

    if not collection_filter:
        collection_filter = {"status": "SUCCESS"}

    if not LIMIT:
        _COUNT = ScanContext.mongo_collection.count_documents(collection_filter)
        LIMIT = _COUNT
    else:
        _COUNT = LIMIT

    db_items = ScanContext.mongo_collection.find(collection_filter, limit=LIMIT)

    LOGGER.info("[1] Writing bulk import headers")
    InitialHTMLNode.write_header()
    ResumptionHTMLNode.write_header()
    Relationship.write_header()
    LOGGER.info("[2] Starting classification and bulk import csv preparation")
    initial_rows = []
    resumption_rows = []
    edge_rows = []
    rows = (initial_rows, resumption_rows, edge_rows)
    with ProcessPool() as pool:
        for doc in tqdm(db_items, total=_COUNT, mininterval=2):
            classify(doc, rows)
    with open(InitialHTMLNode._FILENAME, "w") as InitialHTMLNode.FILE, open(
        ResumptionHTMLNode._FILENAME, "w"
    ) as ResumptionHTMLNode.FILE, open(Relationship._FILENAME, "w") as Relationship.FILE:
        initial_html_writer = csv.writer(InitialHTMLNode.FILE, quoting=csv.QUOTE_NONE)
        resumption_html_writer = csv.writer(ResumptionHTMLNode.FILE, quoting=csv.QUOTE_NONE)
        edge_writer = csv.writer(Relationship.FILE, quoting=csv.QUOTE_NONNUMERIC)
        for row in initial_rows:
            initial_html_writer.writerow(row)
        for row in resumption_rows:
            resumption_html_writer.writerow(row)
        for row in edge_rows:
            edge_writer.writerow(row)
    LOGGER.info("[3] Finishing bulk import preparation")
    # #back up the files
    # shutil.copy("neo4j/import/initial_html.csv", "neo4j/import/initial_html.csv.old")
    # shutil.copy("neo4j/import/resumption_html.csv", "neo4j/import/resumption_html.csv.old")
    # shutil.copy("neo4j/import/html_edges.csv", "neo4j/import/html_edges.csv.old")

    with CACHE_FILE.open("w") as f:
        json.dump(CACHE_KEY, f)


def do_bulk_import():
    LOGGER.info("[4] Bulk import")
    subprocess.call("./neo4j/import_html_nodes.sh", shell=True)
    LOGGER.info("[5] Restarting Neo4J")
    subprocess.call("./neo4j/run_html_neo4j.sh", shell=True)


def main(collection_name=None, collection_filter=None, LIMIT=None):
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        stream=sys.stdout,
    )
    logging.getLogger("neo4j").setLevel(logging.WARNING)
    logging.getLogger("pymongo").setLevel(logging.WARNING)
    ScanContext.initialize(mongo_collection_name=collection_name)
    LOGGER.info(f"Analyzing collection {ScanContext.mongo_collection.full_name}")

    prepare_bulk_import_files(collection_filter=collection_filter, LIMIT=LIMIT)
    do_bulk_import()
    LOGGER.info("[#] Done")


if __name__ == "__main__":
    main()
