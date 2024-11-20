import time
import subprocess
import csv
from tqdm import tqdm
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

import bson
import shutil
import Levenshtein
from utils.botp import BagOfTreePaths
import utils.json_serialization as json
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning, XMLParsedAsHTMLWarning
from bson import ObjectId
from neo4j import Driver as Neo4jDriver
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_serializer,
    model_validator,
)
from pymongo import IndexModel
from pymongo.collection import Collection
from pymongo.errors import DocumentTooLarge, _OperationCancelled
from utils.credentials import mongodb_creds, neo4j_creds
from utils.db import (
    MongoCollection,
    MongoDB,
    Neo4j,
    connect_mongo,
    connect_neo4j,
    get_most_recent_collection_name,
)
from utils.misc import catch_exceptions
from utils.result import Zgrab2ResumptionResult
from utils.result import Connectable, ScanVersion, Zgrab2ResumptionResultStatus
from pathlib import Path
from tqdm import tqdm

_NEO4J_PATH = Path(__file__).parent / "neo4j"
_NEO4J_PATH_IMPORT = _NEO4J_PATH / "import"

LOGGER = logging.getLogger(__name__)

CAPTURE_PERF_STATS = False


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

    def __init__(self, doc_id, ip, domain, version):
        super().__init__(doc_id, ip, domain, version, labels="HTML;INITIAL_HTML")

    def header():
        return ":ID(Initial-ID),doc_id,ip,domain,version,:LABEL"

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

    def __init__(self, initial: InitialHTMLNode, resumption: ResumptionHTMLNode, classification, reason):
        self.initial = initial
        self.resumption = resumption
        self.classification = classification
        # escape , because it is used as delimiter
        self.reason = reason.replace(",", ";")
        # self.edge_writer = edge_writer

    def header():
        return ":START_ID(Initial-ID),:END_ID(Resumption-ID),:TYPE,classification,reason"

    def row(self):
        # classification is a string and needs to be quoted for the import tool
        # return (self.initial_id, self.resumption_id, "RESUMED_AT", f'{self.classification}', f'{self.reason}')
        return (self.initial.id(), self.resumption.id(), "RESUMED_AT", self.classification, self.reason)

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
            reason=classification.reason,
        )
        # edge_writer.writerow(edge.row())
        edge_rows.append(edge.row())


# endregion Bulkimport

# region Indexing


def create_indices():
    # indices on ip and domain
    for typ in ("HTML", "INITIAL_HTML", "REDIRECT_HTML"):
        ScanContext.neo4j.execute_query(
            f"CREATE INDEX node_ip_index_{typ.lower()} IF NOT EXISTS FOR (n:{typ}) ON (n.ip);"
        )
        ScanContext.neo4j.execute_query(
            f"CREATE INDEX node_domain_index_{typ.lower()} IF NOT EXISTS FOR (n:{typ}) ON (n.domain);"
        )
    # create index on edge classification
    ScanContext.neo4j.execute_query(
        "CREATE INDEX edge_classification_index IF NOT EXISTS FOR ()-[r:RESUMED_AT]->() ON (r.classification);"
    )
    # create index on edge classification
    ScanContext.neo4j.execute_query(
        "CREATE INDEX edge_reason_index IF NOT EXISTS FOR ()-[r:RESUMED_AT]->() ON (r.reason);"
    )


# endregion Indexing

# region Similarity Edges


def perform_apoc_query(cypherIterate: str, cypherAction: str, batch_size: int, parallel: bool = True, params=None):
    if LOGGER.isEnabledFor(logging.DEBUG):
        _cypher_action = [ln.strip() for ln in cypherAction.splitlines()]
        while "" in _cypher_action:
            _cypher_action.remove("")

        LOGGER.debug(f"Performing APOC query with action {_cypher_action[-1]!r}")
    parallel_str = "true" if parallel else "false"
    query = f"""
        CALL apoc.periodic.iterate(
        "{cypherIterate}",
        "{cypherAction}",
        {{batchSize:{batch_size}, parallel:{parallel_str}, concurrency: 200}})
        """
    start = time.time()
    res = ScanContext.neo4j.execute_query(query, parameters_=params)
    duration = time.time() - start
    apoc_res = res.records[0]
    LOGGER.info(
        f"""Query finished:
    Execution time : DB {res.summary.result_available_after} ms, APOC {apoc_res['timeTaken']} s, REAL {duration:.2f} s
    Update Stats   : {apoc_res['updateStatistics']}
    Batch Info     : {apoc_res['batch']}
    Operation Info : {apoc_res['operations']}
    Retries        : {apoc_res['retries']}
    Failed Params  : {apoc_res['failedParams']}
    Error Messages : {apoc_res['errorMessages']}"""
    )
    return res


def _execute_query(cypher, params=None, *ret_var: str):
    if params:
        for k in list(params.keys()):
            if isinstance(params[k], set):
                params[k] = list(params[k])
    res = ScanContext.neo4j.execute_query(cypher, params)
    for record in res.records:
        if len(ret_var) == 1:
            yield record[ret_var[0]]
        else:
            yield (record[var] for var in ret_var)


def execute_query(cypher, params=None, *ret_var: str):
    return list(_execute_query(cypher, params, *ret_var))


@dataclass
class Stats:
    QUERY_TIME_RESUMPTIONS: float = 0
    QUERY_TIME_RELATED_INITIAL: float = 0
    QUERY_TIME_RELATED_REDIRECT: float = 0
    # QUERY_TIME_RELATED_REDIRECT_SIMPLE: float = 0
    MERGE_TIME_BLACK_BLUE: float = 0
    MERGE_TIME_YELLOW: float = 0
    MERGE_TIME_PURPLE: float = 0

    def __iadd__(self, other):
        for k in Stats.__annotations__:
            setattr(self, k, getattr(self, k) + getattr(other, k))
        return self

    def __truediv__(self, other):
        ret = {}
        for k in Stats.__annotations__:
            ret[k] = getattr(self, k) / other
        return Stats(**ret)

    def __str__(self) -> str:
        SEP = "\n  "
        total = sum(getattr(self, k) for k in Stats.__annotations__)
        if total == 0:
            return "Stats(0s)"
        return (
            f"Stats({total:10.2f}s:"
            + SEP
            + SEP.join(f"{getattr(self, k):10.2f}s ({getattr(self, k)/total:6.2%}): {k}" for k in Stats.__annotations__)
            + SEP
            + "\n)"
        )


# print(Stats(10, 20, 30, 40, 50, 1.1231253515))
# print()


if CAPTURE_PERF_STATS:

    class StatsCapture(Stats):
        def __init__(self):
            self._values = {k: 0 for k in Stats.__annotations__}
            self._start = None

        def __getattribute__(self, item):
            if item != "_values" and item in self._values:
                self._last_item = item
                return self
            return super().__getattribute__(item)

        def __enter__(self):
            assert self._last_item is not None
            assert self._start is None
            self._start = time.time()
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            self._values[self._last_item] += time.time() - self._start
            self._last_item = None
            self._start = None

        def finalize(self):
            return Stats(**self._values)

else:

    class StatsCapture(Stats):
        def __init__(self):
            self._values = {k: 0 for k in Stats.__annotations__}

        def __getattribute__(self, item: str):
            if item != "_values" and item in self._values:
                return self
            return super().__getattribute__(item)

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

        def finalize(self):
            return None


def build_edges_for_domain(initial_domain: str):
    stats = StatsCapture()
    with stats.QUERY_TIME_RESUMPTIONS as _:
        resumptions = execute_query(
            "MATCH (i:INITIAL_HTML {domain: $domain})-[:WHITE]->(r:REDIRECT_HTML) RETURN i,r",
            {"domain": initial_domain},
            "i",
            "r",
        )
    with stats.QUERY_TIME_RELATED_INITIAL as _:
        nodes_related_to_domain = {
            x.element_id
            for x in execute_query("MATCH (i:INITIAL_HTML {domain: $domain}) RETURN i", {"domain": initial_domain}, "i")
        }
    with stats.MERGE_TIME_PURPLE as _:
        execute_query(
            """
            MATCH (initial_related1: INITIAL_HTML), (initial_related2: INITIAL_HTML)
            WHERE elementId(initial_related1) in $initial_related_nodes
                AND elementId(initial_related2) in $initial_related_nodes
                AND initial_related1 <> initial_related2
            MERGE (initial_related1)-[:PURPLE]->(initial_related2)
            """,
            {
                "initial_related_nodes": nodes_related_to_domain,
            },
        )
    for initial, redirect in resumptions:
        # with stats.QUERY_TIME_RELATED_REDIRECT_SIMPLE as _:
        #     # collect HTMLs that we observed on redirect.ip
        #     _ = {
        #         x.element_id
        #         for x in execute_query(
        #             """
        #         MATCH (relevant_initial:INITIAL_HTML)
        #         WHERE relevant_initial.ip = $ip
        #         RETURN relevant_initial
        #         """,
        #             {"ip": redirect["ip"], "initial_domain": initial_domain},
        #             "relevant_initial",
        #         )
        #     }
        with stats.QUERY_TIME_RELATED_REDIRECT as _:
            # collect all domains that are hosted on redirect.ip
            # for those domains collect all HTMLs
            nodes_related_to_redirect = {
                x.element_id
                for x in execute_query(
                    """
                WITH COLLECT {
                    MATCH (initial2:INITIAL_HTML {ip: $ip })
                    RETURN DISTINCT initial2.domain as domain
                    UNION
                    RETURN $initial_domain as domain
                } as relevant_domains
                MATCH (relevant_initial:INITIAL_HTML)
                WHERE relevant_initial.domain in relevant_domains
                RETURN relevant_initial
                """,
                    {"ip": redirect["ip"], "initial_domain": initial_domain},
                    "relevant_initial",
                )
            }
        if redirect.element_id in nodes_related_to_redirect:
            nodes_related_to_redirect.remove(redirect.element_id)

        initial_related = set(nodes_related_to_domain)
        if initial.element_id in initial_related:
            initial_related.remove(initial.element_id)

        with stats.MERGE_TIME_BLACK_BLUE as _:
            execute_query(
                """
                MATCH (initial: INITIAL_HTML), (redirect: REDIRECT_HTML), (related_node: INITIAL_HTML)
                WHERE elementId(initial)=$initial AND elementId(redirect)=$redirect AND elementId(related_node) in $related_nodes
                MERGE (redirect)-[:BLACK]->(related_node)
                WITH initial, related_node
                WHERE initial <> related_node
                MERGE (initial)-[:BLUE]->(related_node)
                """,
                {
                    "initial": initial.element_id,
                    "redirect": redirect.element_id,
                    "related_nodes": initial_related | nodes_related_to_redirect,
                },
            )

        with stats.MERGE_TIME_YELLOW as _:
            execute_query(
                """
                MATCH (initial_related: INITIAL_HTML), (redirect_related: INITIAL_HTML)
                WHERE elementId(initial_related) in $initial_related_nodes
                    AND elementId(redirect_related) in $redirect_related_nodes
                    AND initial_related <> redirect_related
                MERGE (initial_related)-[:YELLOW]->(redirect_related)
                """,
                {
                    "initial_related_nodes": initial_related,
                    "redirect_related_nodes": nodes_related_to_redirect,
                },
            )
    return stats.finalize()


def maybe_parallel_imap_unordered(func, iterable, parallel):
    if parallel:
        with ProcessPool(32) as pool:
            for res in pool.imap_unordered(func, iterable):
                yield res
    else:
        for res in map(func, iterable):
            yield res


def build_similarity_edges(parallel=True):
    # create WHITE edge for all LOOK_AT_METRICS initial -> resumption
    res = perform_apoc_query(
        """
        MATCH (initial:INITIAL_HTML)-[:RESUMED_AT {classification: 'LOOK_AT_METRICS'}]->(redirect:REDIRECT_HTML)
        RETURN initial, redirect
        """,
        "MERGE (initial)-[:WHITE]->(redirect)",
        10000,
    )
    LOGGER.info(f"Created {res.records[0]['updateStatistics']['relationshipsCreated']:,} new white relationships")

    res = ScanContext.neo4j.execute_query(
        """
    MATCH (x:INITIAL_HTML)-[:WHITE]-(redirect:REDIRECT_HTML)
    RETURN DISTINCT x.domain as domain
    """
    )
    WHITE_redirect_domains: list[str] = [x["domain"] for x in res.records]
    LOGGER.info(f"Found {len(WHITE_redirect_domains):,} white redirect domains")

    progress = tqdm(total=len(WHITE_redirect_domains), smoothing=0.1, mininterval=5, maxinterval=30)
    if CAPTURE_PERF_STATS:
        stats = Stats()
    for i, stat in enumerate(
        maybe_parallel_imap_unordered(build_edges_for_domain, WHITE_redirect_domains, parallel), start=1
    ):
        progress.update()
        if CAPTURE_PERF_STATS:
            stats += stat
            if i % 1000 == 0:
                LOGGER.info(f"Processed {i:,} domains")
                LOGGER.info(stats)
                LOGGER.info(stats / i)

    progress.close()


# endregion Similarity Edges


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
        for doc in tqdm(db_items, total=_COUNT, mininterval=5, file=sys.stdout):
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


def build_edges():
    LOGGER.info("[6] Connecting to Neo4J")
    start = time.time()
    while time.time() - start < 30:
        try:
            ScanContext.neo4j = connect_neo4j(verify_connectivity=True)
            print("connected")
            break
        except:
            print(".", end="")
            time.sleep(1)
    else:
        raise ConnectionError("Could not connect to Neo4J")
    LOGGER.info("[7] Building indices")
    create_indices()
    LOGGER.info("[8] Building similarity edges")
    build_similarity_edges()


def main(collection_name=None, collection_filter=None, LIMIT=None):
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    logging.getLogger("neo4j").setLevel(logging.WARNING)
    ScanContext.initialize(mongo_collection_name=collection_name)
    LOGGER.info(f"Analyzing collection {ScanContext.mongo_collection.full_name}")

    prepare_bulk_import_files(collection_filter=collection_filter, LIMIT=LIMIT)
    do_bulk_import()
    build_edges()


if __name__ == "__main__":
    # main("test")
    # main("ticket_redirection_2024-08-19_19:28", LIMIT=3_000_000)
    main("ticket_redirection_2024-08-19_19:28")
