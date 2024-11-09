import time
import subprocess
import csv
from tqdm import tqdm
from collections import Counter
import datetime
import functools
import heapq
import itertools
import logging
import os
import sys
import time
import warnings
from dataclasses import dataclass
from enum import Enum
from multiprocessing.pool import Pool as ProcessPool
from multiprocessing.pool import ThreadPool
from pprint import pformat, pprint
from typing import Optional, Union
from urllib.parse import urlparse

import bson
import Levenshtein
from utils.botp import BagOfTreePaths
import utils.json_serialization as json
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning, XMLParsedAsHTMLWarning
from bson import ObjectId
from neo4j import GraphDatabase
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


class ScanContext:
    neo4j: GraphDatabase = None
    mongo_collection: Collection = None
    resumption_collection: Collection = None

    @staticmethod
    def initialize(mongo_collection_name=None, *, verify_connectivity=True):

        # ScanContext.neo4j = connect_neo4j(verify_connectivity=verify_connectivity)
        mongodb = connect_mongo(verify_connectivity=verify_connectivity)
        database = mongodb["steckruebe"]
        if not mongo_collection_name:
            mongo_collection_name = get_most_recent_collection_name(
                database, "ticket_redirection_"
            )
            logging.info(f"Using most recent collection: {mongo_collection_name}")
        if not mongo_collection_name:
            raise ValueError("Could not determine most recent collection")
        ScanContext.mongo_collection = database[mongo_collection_name]
        # resumption collection is used for post processing the original collection
        ScanContext.resumption_collection = database[
            f"{mongo_collection_name}_resumptions"
        ]


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
            self.certificate = self._handshake_log["server_certificates"][
                "certificate"
            ]["raw"]
            self.parsed_certificate = self._handshake_log["server_certificates"][
                "certificate"
            ].get("parsed")
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
                logging.info(
                    f"Same location was specified multiple times, reducing to one: {self.location} for {self._ip}"
                )
                self.location = [self.location[0]]
            else:
                logging.warning(
                    f"Multiple distinct locations: {self.location} for {self._ip}"
                )

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

@dataclass
class HTMLNode:
    _FILENAME = ""
    _HEADER_FILENAME = ""
    # dummy writer
    _FILE = open("/dev/null", "w")
    _WRITER = csv.writer(_FILE, quoting=csv.QUOTE_NONE)

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

    def write(self):
        try:
            self._WRITER.writerow(self.row())
        except Exception as e:
            print(self.row())
            raise e

    @classmethod
    def write_header(cls):
        with open(cls._HEADER_FILENAME, "w") as f:
            f.write(cls.header())


class InitialHTMLNode(HTMLNode):
    _FILENAME = "neo4j/import/initial_html.csv"
    _HEADER_FILENAME = "neo4j/import/initial_html_header.csv"
    _FILE = open(_FILENAME, "w")
    _WRITER = csv.writer(_FILE, quoting=csv.QUOTE_NONE)

    def __init__(self, doc_id, ip, domain, version):
        super().__init__(doc_id, ip, domain, version, labels="HTML;INITIAL_HTML")

    def header():
        return ":ID(Initial-ID),doc_id,ip,domain,version,:LABEL"

class ResumptionHTMLNode(HTMLNode):
    _FILENAME = "neo4j/import/resumption_html.csv"
    _HEADER_FILENAME = "neo4j/import/resumption_html_header.csv"
    _FILE = open(_FILENAME, "w")
    _WRITER = csv.writer(_FILE, quoting=csv.QUOTE_NONE)

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


class Relationship:
    _FILENAME = "neo4j/import/html_edges.csv"
    _HEADER_FILENAME = "neo4j/import/html_edges_header.csv"
    _FILE = open(_FILENAME, "w")
    _WRITER = csv.writer(_FILE, quoting=csv.QUOTE_NONNUMERIC)

    def __init__(self, initial_id, resumption_id, classification, reason):
        self.initial_id = initial_id
        self.resumption_id = resumption_id
        self.classification = classification
        # escape , because it is used as delimiter
        self.reason = reason.replace(",", ";")

    def header():
        return ":START_ID(Initial-ID),:END_ID(Resumption-ID),:TYPE,classification,reason"

    def id(self):
        return hash((self.initial_id, self.resumption_id))

    def row(self):
        # classification is a string and needs to be quoted for the import tool
        return (self.initial_id, self.resumption_id, "RESUMED_AT", f'{self.classification}', f'{self.reason}')

    def write(self):
        try:
            self._WRITER.writerow(self.row())
        except Exception as e:
            print(self.row())
            raise e

    @classmethod
    def write_header(cls):
        with open(cls._HEADER_FILENAME, "w") as f:
            f.write(cls.header())

def classify(doc, insert_result: bool = True):
    doc_id = doc["_id"]
    del doc["_id"]
    if "_analyzed" in doc:
        del doc["_analyzed"]
    if "_analysis_errored" in doc:
        del doc["_analysis_errored"]
    result = AnalyzedZgrab2ResumptionResult(**doc)
    # insert all successful initial resumption pairs into the resumption collection and assign a unique id
    initial = InitialHTMLNode(
        doc_id=doc_id,
        ip=result.initial._ip,
        domain=result.domain_from,
        version="TLSv1.2" if result.version is ScanVersion.TLS1_2 else "TLSv1.3",
    )
    initial.write()
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
            version=(
                "TLSv1.2" if result.version is ScanVersion.TLS1_2 else "TLSv1.3"
            ),
        )
        resumption.write()
        edge = Relationship(
            initial_id=initial.id(), resumption_id=resumption.id(), classification=classification.classification.name, reason=classification.reason
        )
        edge.write()

# region Indexing
def create_indices():
    # indices on ip and domain
    index_query = """
        CREATE INDEX node_ip_index IF NOT EXISTS FOR (n:HTML) ON (n.ip);
        """
    ScanContext.neo4j.execute_query(index_query)
    index_query = """
        CREATE INDEX node_domain_index IF NOT EXISTS FOR (n:HTML) ON (n.domain);
        """
    ScanContext.neo4j.execute_query(index_query)
        # create index on edge classification
    index_query = """
        CREATE INDEX edge_classification_index IF NOT EXISTS FOR ()-[r:RESUMED_AT]->() ON (r.classification);
    """
    ScanContext.neo4j.execute_query(index_query)
    # create index on edge classification
    index_query = """
        CREATE INDEX edge_classification_index IF NOT EXISTS FOR ()-[r:RESUMED_AT]->() ON (r.classification);
    """
    ScanContext.neo4j.execute_query(index_query)
# endregion Indexing

# region Similarity Edges
def build_similarity_edges():
    # create TARGET edge for all initial -> resumption
    white_query = """
        CALL apoc.periodic.iterate(
        "MATCH (initial:INITIAL_HTML)-[:RESUMED_AT]->(redirect:REDIRECT_HTML)
        RETURN initial, redirect",
        "MERGE (initial)-[:TARGET]->(redirect)",
        {batchSize:10000, parallel:true})
        """
        # MATCH (initial:INITIAL_HTML)-[:RESUMED_AT]->(redirect:REDIRECT_HTML)
        # MERGE (initial)-[:WHITE]->(redirect)
        # """
    # execute query
    _, summary, _ = ScanContext.neo4j.execute_query(white_query)
    logging.info(f"Created {summary.counters.relationships_created=} new white relationships")
    #print execution time
    logging.info(f"Execution time: {summary.result_available_after} ms")

    # create BLACK edge for each resumption to all other resumptions with same ip
    black_query = """
        CALL apoc.periodic.iterate(
        "MATCH (redirect:REDIRECT_HTML)
        MATCH (redirect2:REDIRECT_HTML)
        WHERE redirect<>redirect2 AND redirect.ip=redirect2.ip
        RETURN redirect, redirect2",
        "MERGE (redirect)-[:BLACK]->(redirect2)",
        {batchSize:10000, parallel:true})
        """
        # MATCH (redirect:HTML:REDIRECT_HTML)
        # MATCH (redirect2:HTML:REDIRECT_HTML)
        # WHERE redirect<>redirect2 AND redirect.ip=redirect2.ip
        # MERGE (redirect)-[:BLACK]->(redirect2)
        # """
    _, summary, _ = ScanContext.neo4j.execute_query(black_query)
    logging.info(f"Created {summary.counters.relationships_created=} new black relationships")
    logging.info(f"Execution time: {summary.result_available_after} ms")

    # create BLUE edge for each initial to all initial with same domain
    # blue_query = """
    #     MATCH (initial:HTML:INITIAL_HTML)
    #     MATCH (initial2:HTML:INITIAL_HTML)
    #     WHERE initial<>initial2 AND initial.domain=initial2.domain
    #     MERGE (initial)-[:BLUE]->(initial2)
    # """
    blue_query = """
        CALL apoc.periodic.iterate(
        "MATCH (initial:INITIAL_HTML)
        MATCH (initial2:INITIAL_HTML)
        WHERE initial<>initial2 AND initial.domain=initial2.domain
        RETURN initial, initial2",
        "MERGE (initial)-[:BLUE]->(initial2)",
        {batchSize:10000, parallel:true})
        """
    _, summary, _ = ScanContext.neo4j.execute_query(blue_query)
    logging.info(f"Created {summary.counters.relationships_created=} new blue relationships")

    # create PURPLE edge between all blue neighbors respectively
    # purple_query = """
    #     MATCH (initial:INITIAL_HTML)-[:BLUE]->(initial2:INITIAL_HTML)
    #     MATCH (initial:INITIAL_HTML)-[:BLUE]->(initial3:INITIAL_HTML)
    #     WHERE initial2<>initial3
    #     MERGE (initial2)-[:PURPLE]->(initial3)
    # """
    purple_query = """
        CALL apoc.periodic.iterate(
        "MATCH (initial:INITIAL_HTML)-[:BLUE]->(initial2:INITIAL_HTML)
        MATCH (initial:INITIAL_HTML)-[:BLUE]->(initial3:INITIAL_HTML)
        WHERE initial2<>initial3
        RETURN initial2, initial3",
        "MERGE (initial2)-[:PURPLE]->(initial3)",
        {batchSize:10000, parallel:true})
        """
    _, summary, _ = ScanContext.neo4j.execute_query(purple_query)
    logging.info(f"Created {summary.counters.relationships_created=} new purple relationships")

    # create GREEN edge for initial -> resumption to all neighbors of resumption
    # green_query = """
    #     MATCH (initial:HTML:INITIAL_HTML)-[:RESUMED_AT]->(redirect:HTML:REDIRECT_HTML)
    #     MATCH (redirect:HTML:REDIRECT_HTML)-[:BLUE|PURPLE|BLACK]-(redirect2:HTML:REDIRECT_HTML)
    #     WHERE redirect<>redirect2
    #     MERGE (initial)-[:GREEN]->(redirect2)
    # """
    green_query = """
        CALL apoc.periodic.iterate(
        "MATCH (initial:INITIAL_HTML)-[:RESUMED_AT]->(redirect:REDIRECT_HTML)
        MATCH (redirect:REDIRECT_HTML)-[:BLUE|PURPLE|BLACK]-(redirect2:REDIRECT_HTML)
        WHERE redirect<>redirect2
        RETURN initial, redirect2",
        "MERGE (initial)-[:GREEN]->(redirect2)",
        {batchSize:10000, parallel:true})
        """
    _, summary, _ = ScanContext.neo4j.execute_query(green_query)
    logging.info(f"Created {summary.counters.relationships_created=} new green relationships")

     # create YELLOW edge for initial -> resumption for all with same domain as initial to all neighbors of resumption
    # yellow_query = """
    #     MATCH (initial:HTML:INITIAL_HTML)-[:RESUMED_AT]->(redirect:HTML:REDIRECT_HTML)
    #     MATCH (initial:HTML:INITIAL_HTML)-[:BLUE]-(initial2:HTML:INITIAL_HTML)
    #     MATCH (redirect:HTML:REDIRECT_HTML)-[:BLUE|PURPLE|BLACK|GREEN]-(redirect2:HTML:REDIRECT_HTML)
    #     MERGE (initial2)-[:YELLOW]->(redirect2)
    # """
    yellow_query = """
        CALL apoc.periodic.iterate(
        "MATCH (initial:INITIAL_HTML)-[:RESUMED_AT]->(redirect:REDIRECT_HTML)
        MATCH (initial:INITIAL_HTML)-[:BLUE]-(initial2:INITIAL_HTML)
        MATCH (redirect:REDIRECT_HTML)-[:BLUE|PURPLE|BLACK|GREEN]-(redirect2:REDIRECT_HTML)
        RETURN initial2, redirect2",
        "MERGE (initial2)-[:YELLOW]->(redirect2)",
        {batchSize:10000, parallel:true})
        """
    _, summary, _ = ScanContext.neo4j.execute_query(yellow_query)
    print(f"Created {summary.counters.relationships_created=} new yellow relationships")

    # deduplicate all relationships
    # deduplicate_query = """
    #     MATCH (a)-[r:PURPLE]->(b)
    #     WITH a, b, collect(r) AS rels
    #     WHERE size(rels) > 1
    #     FOREACH (r IN rels[1..] | DELETE r)
    # """


def analyze_collection(collection_filter=None):
    # ""index for analyzed flag")
    # ScanContext.mongo_collection.create_indexes(
    #     [
    #         IndexModel("_analyzed"),
    #         IndexModel([("status", 1), ("_analyzed", 1)]),
    #     ]
    # )
    if not collection_filter:
        collection_filter = { "status": "SUCCESS" }

    _COUNT = ScanContext.mongo_collection.count_documents(collection_filter)
    db_items = ScanContext.mongo_collection.find(collection_filter)

    # logging.info("[1] Writing bulk import headers")
    # InitialHTMLNode.write_header()
    # ResumptionHTMLNode.write_header()
    # Relationship.write_header()
    # logging.info("[2] Starting classification and bulk import csv preparation")
    # with ProcessPool() as pool:
    #     for x in tqdm(pool.imap_unordered(classify, db_items), total=_COUNT, mininterval=5, file=sys.stdout):
    #         pass
    # logging.info("[3] Finishing bulk import preparation")
    # # we manage the file handles ourselves, so we need to close them
    # InitialHTMLNode._FILE.flush()
    # InitialHTMLNode._FILE.close()
    # ResumptionHTMLNode._FILE.flush()
    # ResumptionHTMLNode._FILE.close()
    # Relationship._FILE.flush()
    # Relationship._FILE.close()
    # logging.info("[4] Bulk import")
    # subprocess.call("./neo4j/import_html_nodes.sh", shell=True)
    # logging.info("[5] Restarting Neo4J")
    # subprocess.call("./neo4j/run_html_neo4j.sh", shell=True)
    # time.sleep(30)
    ScanContext.neo4j = connect_neo4j(verify_connectivity=True)
    logging.info("[6] Building indices")
    create_indices()
    logging.info("[7] Building similarity edges")
    build_similarity_edges()


def main(collection_name=None, collection_filter=None):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    ScanContext.initialize(mongo_collection_name=collection_name)
    logging.info(f"Analyzing collection {ScanContext.mongo_collection.full_name}")
    analyze_collection(collection_filter=collection_filter)


# main("test")
main("ticket_redirection_2024-08-19_19:28")
