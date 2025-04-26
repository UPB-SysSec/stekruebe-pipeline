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
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import ProcessPoolExecutor

import bson
import Levenshtein
import utils.json_serialization as json
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning, XMLParsedAsHTMLWarning
from bson import ObjectId
from neo4j import Driver as Neo4jDriver
from neo4j import RoutingControl
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
import numpy as np
import scipy.stats as stats
import matplotlib.pyplot as plt

from collections import defaultdict
import pickle

from collections import Counter
import os
from time import sleep
from random import randint

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)
warnings.filterwarnings("ignore", "Degrees of freedom <= 0 for slice")
warnings.filterwarnings("ignore", "invalid value encountered in scalar divide")

LOGGER = logging.getLogger(__name__)
CONFIDENCE_VERSION = 2


class ScanContext:
    neo4j: Neo4jDriver = None
    resumption_collection: Collection = None

    @staticmethod
    def initialize(*, verify_connectivity=True):
        ScanContext.neo4j = connect_neo4j(verify_connectivity=verify_connectivity)


def write_transaction(tx, rel_id, metric, domainname, confidence):
    query = """
    MATCH ()-[r]->()
    WHERE elementId(r) = $rel_id
    SET r[$property_name_1] = $property_value_1
    SET r[$property_name_2] = $property_value_2
    """
    x = tx.run(
        query,
        rel_id=rel_id,
        property_name_1=metric + "_maxconf_domain",
        property_value_1=domainname,
        property_name_2=metric + "_maxconf_val",
        property_value_2=confidence,
    )


def write_result(rel_id, target_sim, domain, confidence):
    try:
        x = ScanContext.neo4j.session().execute_write(
            write_transaction, rel_id=rel_id, metric=target_sim, domainname=domain, confidence=confidence
        )
    except Exception as e:
        print("Ex", e, type(e))


def __confidence_statistics(y, resumption_similarity, cdf_x):
    if -2 in y:
        return 0.0
    n = len(y)
    if n < 2:
        return 0.0
    mean_y = np.mean(y)
    # error_y_1 = stats.sem(y, nan_policy='propagate') or 1e-12
    # Mathematical hack so things go wooosh
    error_y = (np.std(y, ddof=1, mean=mean_y) / np.sqrt(n - 1)) or 1e-12
    z_value_y = abs((resumption_similarity - mean_y) / error_y)
    cdf_y = stats.norm.sf(z_value_y)
    return (cdf_y * 2) - (cdf_x * 2)


TARGET_SIMS = [
    "similarity_levenshtein",
    "similarity_levenshtein_header",
    "similarity_bag_of_paths",
    "similarity_radoy_header",
]


def calculate_confidence(r, ir_id):
    target_relationship = r.get("IR")  # white edge
    other_a = r.get("other_a")  # blue/purple edges
    a_b = r.get("a_b")  # green edges
    ScanContext.neo4j.execute_query(
        "MATCH ()-[IR:SIM]->() WHERE elementId(IR)=$ir_id SET IR.computed_confidences=$version",
        {
            "ir_id": ir_id,
            "version": CONFIDENCE_VERSION,
        },
    )
    for target_sim in TARGET_SIMS:
        resumtionsimilarity = target_relationship.get(target_sim)
        if resumtionsimilarity is None:
            write_result(ir_id, target_sim, "", "")
            continue
        if target_relationship == "similarity_radoy_header" and resumtionsimilarity == -2:
            write_result(ir_id, target_sim, "", 0)
            continue
        samesitesimilarities = np.array([a.get(target_sim) for a in other_a if a.get(target_sim) is not None])

        if len(samesitesimilarities) == 0:
            write_result(ir_id, target_sim, "", "")
            continue

        mean_x = np.mean(samesitesimilarities)
        error_x = (np.std(samesitesimilarities, ddof=1, mean=mean_x) / np.sqrt(len(samesitesimilarities) - 1)) or 1e-12
        z_value_x = abs((resumtionsimilarity - mean_x) / error_x)
        cdf_x = stats.norm.sf(z_value_x)

        # -1 indicates strong confidence that we have a.com, +1 indicates strong confidence that we resumed b.com, 0 means we don't know cause it either doesn't match any or both
        # ab = itertools.groupby(r.get("a_b"), lambda x : x[0])
        abc = defaultdict(list)
        for x in a_b:
            val = x[1].get(target_sim)
            if val is not None:
                abc[x[0]].append(val)

        if len(abc) == 0:
            write_result(r.get("id"), target_sim, "", "")
            continue

        confidence_per_domain = [
            (k, __confidence_statistics(np.array(v), resumtionsimilarity, cdf_x)) for k, v in abc.items()
        ]
        maximum_confidence = max(confidence_per_domain, key=lambda x: x[1])

        # confidence_per_domain.sort(key=lambda x:x[1], reverse=True)

        write_result(r.get("id"), target_sim, maximum_confidence[0], float(maximum_confidence[1]))


def calculate_for_edge(ids):
    i_id, ir_id = ids
    res = ScanContext.neo4j.execute_query(
        """
            MATCH (I)-[IR:SIM]-()
            WHERE elementId(I) = $i_id
              AND elementId(IR) = $ir_id 
            WITH I, IR

            // Collect other_a relations
            CALL (I) {
                MATCH (a:INITIAL_HTML)-[A:SIM]-(b:INITIAL_HTML)
                USING INDEX a:INITIAL_HTML(domain)
                WHERE a.domain = I.domain
                  AND b.domain = I.domain
                RETURN COLLECT(A) AS other_a
            }
            // Collect a_b relations
            CALL (I) {
                MATCH (I)-[B:SIM]-(b:HTML)
                WHERE b.domain <> I.domain
                RETURN COLLECT([b.domain, B]) AS a_b
            }
            RETURN IR, other_a, a_b
        """,
        {"i_id": i_id, "ir_id": ir_id},
    )

    for r in res.records:
        # uture = executor.submit(calculate_confidence, r)
        calculate_confidence(r, ir_id)


def maybe_parallel_imap_unordered(func, iterable, parallel):
    if parallel:
        with ProcessPool() as pool:
            for res in pool.imap_unordered(func, iterable):
                yield res
    else:
        for res in map(func, iterable):
            yield res


def calculate():
    # with ThreadPoolExecutor() as executor:
    for metric in (
        "similarity_levenshtein",
        "similarity_levenshtein_header",
        "similarity_bag_of_paths",
        "similarity_radoy_header",
    ):
        ScanContext.neo4j.execute_query(
            f"CREATE INDEX sim_{metric}_maxconf_val IF NOT EXISTS FOR ()-[r:SIM]->() ON (r.{metric}_maxconf_val);"
        )
    ScanContext.neo4j.execute_query(
        f"CREATE INDEX sim_computed_confidences IF NOT EXISTS FOR ()-[r:SIM]->() ON (r.computed_confidences);"
    )

    assert isinstance(CONFIDENCE_VERSION, int)
    _BASE_QUERY = (
        """
    MATCH (I:INITIAL_HTML)-[IR:SIM { first_color: "WHITE" }]-()
    WHERE IR.computed_confidences IS NULL
       OR IR.computed_confidences<"""
        + str(CONFIDENCE_VERSION)
        + """
    """
    )

    total = ScanContext.neo4j.execute_query(_BASE_QUERY + " RETURN COUNT(IR) AS total").records[0].get("total")
    print("Found", total, "edges to compute confidences for")

    with ScanContext.neo4j.session() as session:
        res = session.run(_BASE_QUERY + "RETURN elementId(I) as i_id,elementId(IR) as ir_id")
        res = map(lambda x: (x.get("i_id"), x.get("ir_id")), res)
        progress = tqdm(total=total, smoothing=0.1, mininterval=5, maxinterval=30, dynamic_ncols=True)
        for _ in maybe_parallel_imap_unordered(calculate_for_edge, res, True):
            progress.update()


def main():
    ScanContext.initialize()
    start = time.time()
    calculate()

    print(time.time() - start)


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
