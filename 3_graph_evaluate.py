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

        ScanContext.neo4j = connect_neo4j(verify_connectivity=verify_connectivity)
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


def bson_length(doc):
    if isinstance(doc, dict):
        return len(bson.BSON.encode(doc))
    return -1


@dataclass
class HTMLNode:
    _FILENAME = ""
    _HEADER_FILENAME = ""
    # dummy writer
    _WRITER = csv.writer(open("/dev/null", "w"))

    def __init__(self, html_id, ip, domain, version, labels="HTML"):
        self.html_id = html_id
        self.ip = ip
        self.domain = domain
        self.version = version
        self.labels = labels

    def header():
        return ":ID,html_id,ip,domain,version,:LABEL"

    def __hash__(self):
        return hash((self.html_id, self.ip, self.domain, self.version))

    def row(self):
        return (
            hash(self),
            self.html_id,
            self.ip,
            self.domain,
            self.version,
            self.labels,
        )

    def write(self):
        self._WRITER.writerow(self.row())

    def write_header():
        with open(_HEADER_FILENAME, "w") as f:
            f.write(header())


class InitialHTMLNode(HTMLNode):
    _FILENAME = "initial_html.csv"
    _HEADER_FILENAME = "initial_html_header.csv"
    _WRITER = csv.writer(open(_FILENAME, "w"))

    def __init__(self, html_id, ip, domain, version):
        super().__init__(html_id, ip, domain, version, labels="HTML;INITIAL_HTML")


class ResumptionHTMLNode(HTMLNode):
    _FILENAME = "resumption_html.csv"
    _HEADER_FILENAME = "resumption_html_header.csv"
    _WRITER = csv.writer(open(_FILENAME, "w"))

    def __init__(self, html_id, ip, domain, version):
        super().__init__(html_id, ip, domain, version, labels="HTML;REDIRECT_HTML")


class Relationship:
    _FILENAME = "html_edges.csv"
    _HEADER_FILENAME = "html_edges_header.csv"
    _WRITER = csv.writer(open(_FILENAME, "a"))

    def __init__(self, initial_id, resumption_id):
        self.initial_id = initial_id
        self.resumption_id = resumption_id

    def header():
        return ":START_ID,:END_ID,:TYPE"

    def __hash__(self):
        return hash((self.initial_id, self.resumption_id))

    def row(self):
        return (self.initial_id, self.resumption_id, "RESUMED_AT")

    def write(self):
        self._WRITER.writerow(self.row())

    def write_header():
        with open(_HEADER_FILENAME, "w") as f:
            f.write(header())


def write_resumption_tx(
    tx, initial_id, resumption_id, domain, initial_ip, version, resumption_ip
):
    tx.run(
        """
        MERGE (initial:HTML:INITIAL_HTML {initial_id: $initial_id, domain: $domain, ip: $initial_ip, version: $version})
        MERGE (redirect:HTML:REDIRECT_HTML {resumption_id: $resumption_id, ip: $resumption_ip, domain: $domain, version: $version})
        MERGE (initial)-[:RESUMED_AT]->(redirect)
        """,
        initial_id=initial_id,
        domain=domain,
        initial_ip=initial_ip,
        version=version,
        resumption_id=resumption_id,
        resumption_ip=resumption_ip,
    )


def transcribe_to_graphdb(doc, insert_result: bool = True):
    doc_id: ObjectId = doc["_id"]
    _doc_size = bson_length(doc)
    del doc["_id"]
    if "_analyzed" in doc:
        del doc["_analyzed"]

    result = AnalyzedZgrab2ResumptionResult(**doc)
    # insert all successful initial resumption pairs into the resumption collection and assign a unique id
    initial_id = ObjectId()
    initial = InitialHTMLNode(
        html_id=initial_id,
        ip=result.initial._ip,
        domain=result.domain_from,
        version="TLSv1.2" if result.version is ScanVersion.TLS1_2 else "TLSv1.3",
    )
    initial.write()
    for i, redirect in enumerate(result.redirect):
        if redirect.resumed:
            resumption = {
                "initial": result.initial._zgrabHttpOutput,
                "initial_id": initial_id,
                "redirect": redirect._zgrabHttpOutput,
                "resumption_id": ObjectId(),
            }
            ScanContext.resumption_collection.insert_one(resumption)
            resumption = ResumptionHTMLNode(
                html_id=resumption["resumption_id"],
                ip=redirect._ip,
                domain=result.domain_from,
                version=(
                    "TLSv1.2" if result.version is ScanVersion.TLS1_2 else "TLSv1.3"
                ),
            )
            resumption.write()
            edge = Relationship(
                initial_id=hash(initial), resumption_id=hash(resumption)
            )
            edge.write()
            # _ = session.execute_write(
            #     write_resumption_tx,
            #     initial_id=str(resumption["initial_id"]),
            #     domain=result.domain_from,
            #     resumption_id=str(resumption["resumption_id"]),
            #     initial_ip=result.initial._ip,
            #     version=(
            #         "TLSv1.2" if result.version is ScanVersion.TLS1_2 else "TLSv1.3"
            #     ),
            #     resumption_ip=redirect._ip,
            # )


def build_similarity_edges():
    # create TARGET edge for all initial -> resumption
    white_query = """
        MATCH (initial:HTML:INITIAL_HTML)-[:RESUMED_AT]->(redirect:HTML:REDIRECT_HTML)
        MERGE (initial)-[:WHITE]->(redirect)
        """
    # execute query
    _, summary, _ = ScanContext.neo4j.execute_query(white_query)
    print(f"Created {summary.counters.relationships_created=} new white relationships")

    # create BLACK edge for each resumption to all other resumptions with same ip
    black_query = """
        MATCH (redirect:HTML:REDIRECT_HTML)
        MATCH (redirect2:HTML:REDIRECT_HTML)
        WHERE redirect<>redirect2 AND redirect.ip=redirect2.ip
        MERGE (redirect)-[:BLACK]->(redirect2)
        """
    _, summary, _ = ScanContext.neo4j.execute_query(black_query)
    print(f"Created {summary.counters.relationships_created=} new black relationships")

    # create BLUE edge for each initial to all initial with same domain
    blue_query = """
        MATCH (initial:HTML:INITIAL_HTML)
        MATCH (initial2:HTML:INITIAL_HTML)
        WHERE initial<>initial2 AND initial.domain=initial2.domain
        MERGE (initial)-[:BLUE]->(initial2)
    """
    _, summary, _ = ScanContext.neo4j.execute_query(blue_query)
    print(f"Created {summary.counters.relationships_created=} new blue relationships")

    # create PURPLE edge between all blue neighbors respectively
    purple_query = """
        MATCH (initial:INITIAL_HTML)-[:BLUE]->(initial2:INITIAL_HTML)
        MATCH (initial:INITIAL_HTML)-[:BLUE]->(initial3:INITIAL_HTML)
        WHERE initial2<>initial3
        MERGE (initial2)-[:PURPLE]->(initial3)
    """
    _, summary, _ = ScanContext.neo4j.execute_query(purple_query)
    print(f"Created {summary.counters.relationships_created=} new purple relationships")

    # create GREEN edge for initial -> resumption to all neighbors of resumption
    green_query = """
        MATCH (initial:HTML:INITIAL_HTML)-[:RESUMED_AT]->(redirect:HTML:REDIRECT_HTML)
        MATCH (redirect:HTML:REDIRECT_HTML)-[:BLUE|PURPLE|BLACK]-(redirect2:HTML:REDIRECT_HTML)
        WHERE redirect<>redirect2
        MERGE (initial)-[:GREEN]->(redirect2)
    """
    _, summary, _ = ScanContext.neo4j.execute_query(green_query)
    print(f"Created {summary.counters.relationships_created=} new green relationships")

    # create YELLOW edge for initial -> resumption for all with same domain as initial to all neighbors of resumption
    yellow_query = """
        MATCH (initial:HTML:INITIAL_HTML)-[:RESUMED_AT]->(redirect:HTML:REDIRECT_HTML)
        MATCH (initial:HTML:INITIAL_HTML)-[:BLUE]-(initial2:HTML:INITIAL_HTML)
        MATCH (redirect:HTML:REDIRECT_HTML)-[:BLUE|PURPLE|BLACK|GREEN]-(redirect2:HTML:REDIRECT_HTML)
        MERGE (initial2)-[:YELLOW]->(redirect2)
    """
    _, summary, _ = ScanContext.neo4j.execute_query(yellow_query)
    print(f"Created {summary.counters.relationships_created=} new yellow relationships")

    # deduplicate all relationships
    deduplicate_query = """
        MATCH (a)-[r:PURPLE]->(b)
        WITH a, b, collect(r) AS rels
        WHERE size(rels) > 1
        FOREACH (r IN rels[1..] | DELETE r)
    """


def analyze_collection(collection_filter=...):
    if collection_filter is ...:
        collection_filter = {"status": "SUCCESS", "_analyzed": {"$ne": True}}
    logging.info("Creating index for analyzed flag")
    ScanContext.mongo_collection.create_indexes(
        [
            IndexModel("_analyzed"),
            IndexModel([("status", 1), ("_analyzed", 1)]),
        ]
    )

    # results = {typ: dict() for typ in ResumptionClassificationType}
    # db_items = ScanContext.mongo_collection.find(collection_filter)
    # logging.info("Counting documents")
    # _COUNT = ScanContext.mongo_collection.count_documents(collection_filter)
    print("[1] Starting transcribing to graphdb")
    # with ProcessPool() as pool:
    #     for x in tqdm(pool.imap_unordered(transcribe_to_graphdb, db_items), total=_COUNT, mininterval=5, file=sys.stdout):
    #         pass
    print("[2] Finished transcribing to graphdb")
    print("[3] Writing headers")
    InitialHTMLNode.write_header()
    ResumptionHTMLNode.write_header()
    Relationship.write_header()
    print("[4] Building similarity edges")
    # build_similarity_edges()


def main(collection_name=None, collection_filter=...):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    ScanContext.initialize(mongo_collection_name=collection_name)
    analyze_collection(collection_filter=collection_filter)


# main("test")
main("ticket_redirection_2024-08-19_19:28")
