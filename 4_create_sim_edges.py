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
    # SIM analyzed
    ScanContext.neo4j.execute_query(
        "CREATE INDEX edge_similarity_analyzed IF NOT EXISTS FOR ()-[r:SIM]->() ON (r.analyzed);"
    )
    # Similarity metrics
    for sim in ("levenshtein", "levenshtein_header", "radoy_header", "bag_of_paths"):
        ScanContext.neo4j.execute_query(
            f"CREATE INDEX edge_similarity_{sim} IF NOT EXISTS FOR ()-[r:SIM]->() ON (r.similarity_{sim});"
        )


# endregion Indexing

# region Similarity Edges


def perform_apoc_query(
    cypherIterate: str, cypherAction: str, batch_size: int, parallel: bool = True, concurrency=200, params=None
):
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
        {{batchSize:{batch_size}, parallel:{parallel_str}, concurrency: {concurrency}}})
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


def build_sim_edges():
    ScanContext.neo4j.execute_query(
        f"CREATE INDEX edge_similarity_first_color IF NOT EXISTS FOR ()-[r:SIM]->() ON (r.first_color);"
    )
    for color in (
        "WHITE",
        "BLACK",
        "BLUE",
        "PURPLE",
        "YELLOW",
    ):
        LOGGER.info(f"Building similarity edges for {color}")
        ScanContext.neo4j.execute_query(
            f"CREATE INDEX edge_similarity_has_{color} IF NOT EXISTS FOR ()-[r:SIM]->() ON (r.has_{color});"
        )
        perform_apoc_query(
            f"""
            MATCH (a)-[:{color}]-(b)
            WHERE elementId(a)<elementId(b)
            return a,b
            """,
            f"""
            MERGE (a)-[r:SIM]->(b)
            ON CREATE SET r.first_color='{color}', r.analyzed=false
            SET r.has_{color}=True;
            """,
            10000,
            parallel=False,
        )
        LOGGER.info(f"Created {color} similarity edges")


# endregion Similarity Edges


def build_edges():
    LOGGER.info("[ ] Connecting to Neo4J")
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
    LOGGER.info("[1] Building indices")
    create_indices()
    LOGGER.info("[2] Building similarity edges")
    build_similarity_edges()
    LOGGER.info("[3] Postprocessing similarity edges (creating SIM edges)")
    build_sim_edges()


def main(collection_name=None, collection_filter=None, LIMIT=None):
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    logging.getLogger("neo4j").setLevel(logging.WARNING)
    ScanContext.initialize(mongo_collection_name=collection_name)
    LOGGER.info(f"Analyzing collection {ScanContext.mongo_collection.full_name}")
    build_edges()
    LOGGER.info("[#] Done")


if __name__ == "__main__":
    # main("test")
    # main("ticket_redirection_2024-08-19_19:28", LIMIT=3_000_000)
    main()
