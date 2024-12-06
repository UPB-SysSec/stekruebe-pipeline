import datetime
import functools
import heapq
import itertools
import logging
import os
import sys
import time
import warnings
from collections import Counter
from dataclasses import dataclass
from enum import Enum
from multiprocessing.pool import Pool as ProcessPool
from multiprocessing.pool import ThreadPool
from pprint import pformat, pprint
from typing import Optional, Union
from urllib.parse import urlparse

import bson
import Levenshtein
import utils.json_serialization as json
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning, XMLParsedAsHTMLWarning
from bson import ObjectId
from neo4j import Driver as Neo4jDriver
from neo4j import GraphDatabase
from neo4j.graph import Node
from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator, model_serializer, model_validator
from pymongo import IndexModel
from pymongo.collection import Collection
from pymongo.errors import DocumentTooLarge, _OperationCancelled
from utils.botp import BagOfTreePaths
from utils.credentials import mongodb_creds, neo4j_creds
from utils.db import MongoCollection, MongoDB, Neo4j, connect_mongo, connect_neo4j, get_most_recent_collection_name
from utils.misc import catch_exceptions
from utils.result import Zgrab2ResumptionResult
from tqdm import tqdm

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

LOGGER = logging.getLogger(__name__)


class ScanContext:
    neo4j: Neo4jDriver = None
    mongo_collection: Collection = None
    resumption_collection: Collection = None

    @staticmethod
    def initialize(mongo_collection_name=None, *, verify_connectivity=True):
        ScanContext.neo4j = connect_neo4j(verify_connectivity=verify_connectivity)

        mongodb = connect_mongo(verify_connectivity=verify_connectivity)
        database = mongodb["steckruebe"]
        if not mongo_collection_name:
            mongo_collection_name = get_most_recent_collection_name(database, "ticket_redirection_")
            logging.info(f"Using most recent collection: {mongo_collection_name}")
        if not mongo_collection_name:
            raise ValueError("Could not determine most recent collection")
        ScanContext.mongo_collection = database[mongo_collection_name]


# region Actual Metrics


# @functools.lru_cache(maxsize=1024 * 1024 * 10)
@functools.wraps(Levenshtein.ratio)
@catch_exceptions
def levenshtein_ratio(a, b):
    return Levenshtein.ratio(a, b)


# Header can contains title, style, base(?), link, meta, script, noscript
# For meta, see https://gist.github.com/lancejpollard/1978404
def compare_entry(entry1, entry2):
    if entry1 is None or entry2 is None:
        return False
    if entry1.name == "script" and entry2.name == "script":
        if entry1.has_attr("nonce"):
            entry1["nonce"] = "rand"
        if entry2.has_attr("nonce"):
            entry2["nonce"] = "rand"
        if entry1.has_attr("src") and entry2.has_attr("src"):
            src1 = entry1["src"].split("?")[0]
            src2 = entry2["src"].split("?")[0]
            # TODO Should they be completely equal?
            return src1 == src2
        if Levenshtein.ratio(str(entry1), str(entry2)) > 0.75:
            return True

    if entry1.name == "link" and entry2.name == "link":
        if entry1.has_attr("nonce"):
            entry1["nonce"] = "rand"
        if entry2.has_attr("nonce"):
            entry2["nonce"] = "rand"
        if entry1.has_attr("rel") and entry2.has_attr("rel") and entry1["rel"] != entry2["rel"]:
            return False
        if entry1.has_attr("size") and entry2.has_attr("size") and entry1["size"] != entry2["size"]:
            return False
        if entry1.has_attr("href") and entry2.has_attr("href"):
            src1 = entry1["href"].split("?")[0]
            src2 = entry2["href"].split("?")[0]
            # TODO Should they be completely equal?
            return src1 == src2
        return False

    if entry1.name == entry2.name == "style":
        if Levenshtein.ratio(str(entry1), str(entry2)) > 0.9:
            return True

    if entry1.name == "title" and entry2.name == "title":
        # We can't match titles, but we hope that both have a title tag
        return True
    if entry1.name == "meta" and entry2.name == "meta":
        if entry1.has_attr("name") and entry2.has_attr("name") and entry1["name"] == entry2["name"]:
            # Almost all meta tags are language dependent, and we can't match language dependent things,
            # but if both meta tags are there we say they match somewhat
            if entry1.has_attr("content") and entry2.has_attr("content"):
                if entry1["name"] in ["viewport", "robots"]:
                    return entry1["content"] == entry2["content"]
                else:
                    return True
        if entry1.has_attr("http-equiv") and entry2.has_attr("http-equiv"):
            return entry1["http-equiv"] == entry2["http-equiv"]

    if entry1.name == entry2.name == "noscript":
        return True

    return False


@catch_exceptions
def radoy_header_ratio(a, b):
    soup1 = BeautifulSoup(a, "html.parser")
    soup2 = BeautifulSoup(b, "html.parser")
    head1 = soup1.head
    head2 = soup2.head
    if head1 is None and head2 is not None or head1 is not None and head2 is None:
        return 0
    if head1 is None and head2 is None:
        # This is kind of a similar, but we set -1 since our test  is not applicable
        return -1

    penalty = 0
    penalty += 0.5 * (abs(len(list(head1.children)) - len(list(head2.children))) ** 1.4)

    for x, y in itertools.zip_longest(head1.children, head2.children):
        if x != y and not compare_entry(x, y):
            # Penalty for mismatch (deducted when found in the next step)
            penalty += 1.25
            for r in head2.find_all(x.name) if x is not None else head1.find_all(y.name):
                if x == r:
                    # Exact match, deduct almost all penalty, still at wrong position
                    penalty -= 1
                if compare_entry(x if x is not None else y, r):
                    # We found a similar enough entry so let's deduct the penalty partly (position was still wrong)
                    penalty -= 0.75
                    break

    num_header_elements = len(list(soup1.head.children))
    if num_header_elements == 0:
        return 0
    return max(0, min(1, 1 - (penalty / num_header_elements)))


def extract_head(html: str, tag="head"):
    # naive way to find head
    start = html.find(f"<{tag}")
    end = html.find(f"</{tag}")
    if start == -1 and end == -1:
        # no head in here
        return ""
    if end == -1:
        # end was probably cut off
        return html[start:]
    return html[start:end]


@catch_exceptions
def levenshtein_header_similarity(a, b):
    head_a = extract_head(a)
    head_b = extract_head(b)
    if not head_a.strip() or not head_b.strip():
        return -1
    return levenshtein_ratio(head_a, head_b)


@catch_exceptions
def bag_of_paths_similarity(a, b):
    bag1 = BagOfTreePaths(a)
    bag2 = BagOfTreePaths(b)
    return bag1.similarity(bag2)


# endregion Actual Metrics


def get_body(doc_id: bytes, redirect_index: Optional[int]):
    if redirect_index is not None:
        projection = {"body": {"$arrayElemAt": ["$redirect.data.http.result.response.body", redirect_index]}}
    else:
        projection = {"body": "$initial.data.http.result.response.body"}
    ret = ScanContext.mongo_collection.find_one({"_id": ObjectId(doc_id)}, projection=projection)
    if "body" not in ret:
        return None
    return ret["body"]


@dataclass
class NodeToAnalyze:
    doc_id: bytes
    redirect_index: Optional[int]

    def __init__(self, node):
        self.doc_id = bytes.fromhex(node["doc_id"])
        if "REDIRECT_HTML" in node.labels:
            self.redirect_index = int(node["redirect_index"])
        else:
            assert "INITIAL_HTML" in node.labels
            self.redirect_index = None

    def get_body(self):
        return get_body(self.doc_id, self.redirect_index)


@dataclass
class RelationToAnalyze:
    a: NodeToAnalyze
    b: NodeToAnalyze
    relation_id: str

    def __init__(self, row):
        self.a = NodeToAnalyze(row["a"])
        self.b = NodeToAnalyze(row["b"])
        self.relation_id = row["rId"]


def compute_similarities(rel: RelationToAnalyze):
    a_body = rel.a.get_body()
    b_body = rel.b.get_body()

    if a_body is None or b_body is None:
        similarities = {}
    else:
        similarities = {
            "levenshtein": levenshtein_ratio(a_body, b_body),
            "levenshtein_header": levenshtein_header_similarity(a_body, b_body),
            "radoy_header": radoy_header_ratio(a_body, b_body),
            "bag_of_paths": bag_of_paths_similarity(a_body, b_body),
        }

    ScanContext.neo4j.execute_query(
        """
        MATCH ()-[r:SIM]->()
        WHERE elementId(r) = $relation_id
        SET r.analyzed = true
        FOREACH (k IN keys($similarities) | SET r["similarity_"+k] = $similarities[k])
        """,
        {
            "relation_id": rel.relation_id,
            "similarities": similarities,
        },
    )


def maybe_parallel_imap_unordered(
    func,
    iterable,
    parallel,
):
    if parallel:
        with ProcessPool(32) as pool:
            for res in pool.imap_unordered(func, iterable, chunksize=100):
                yield res
    else:
        for res in map(func, iterable):
            yield res


def evaluate_sim_edges(color: str):
    BASE_QUERY = "MATCH (a)-[r:SIM {analyzed:false, first_color: $color}]->(b) "
    BASE_QUERY_PARAMS = {"color": color}
    total = ScanContext.neo4j.execute_query(BASE_QUERY + "RETURN count(r) as total", BASE_QUERY_PARAMS)
    total = total.records[0]["total"]
    if total == 0:
        LOGGER.info(f"Processing color {color} is already done")
        return
    LOGGER.info(f"Processing {total:,} edges for color {color}")
    with ScanContext.neo4j.session() as session:
        res = session.run(BASE_QUERY + "RETURN a, elementId(r) as rId, b", BASE_QUERY_PARAMS)
        res = map(RelationToAnalyze, res)
        for _ in tqdm(
            maybe_parallel_imap_unordered(compute_similarities, res, True),
            mininterval=1,
            maxinterval=120,
            total=total,
        ):
            # just count progress
            pass


def main(collection_name=None):
    global proc_pool

    ScanContext.initialize(mongo_collection_name=collection_name)

    LOGGER.info(f"Analyzing collection {ScanContext.mongo_collection.full_name}")
    for color in (
        "WHITE",
        "BLACK",
        "BLUE",
        "PURPLE",
        "YELLOW",
    ):
        evaluate_sim_edges(color)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s | %(process)d %(processName)s - %(name)s.%(funcName)s: %(message)s",
        stream=sys.stdout,
    )
    logging.getLogger("neo4j").setLevel(logging.WARNING)
    logging.getLogger("neo4j.pool").setLevel(logging.ERROR)
    logging.getLogger("pymongo").setLevel(logging.WARNING)
    try:
        main()
    except:
        LOGGER.exception("Error in main")
        raise
