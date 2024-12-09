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


def calculate_confidence(same_site_similarities, cross_site_similarities, resumption_similarity, debug=False):
    mean_x = np.mean(same_site_similarities)
    mean_y = np.mean(cross_site_similarities)
    if debug:
        print("Mean X", mean_x, "Mean Y", mean_y)

    error_x = stats.sem(same_site_similarities)
    error_y = stats.sem(cross_site_similarities)
    if error_x == 0.0:
        error_x = 0.000000000001
    if error_y == 0.0:
        error_y = 0.000000000001

    z_value_x = abs((resumption_similarity - mean_x) /error_x)
    z_value_y = abs((resumption_similarity - mean_y) /error_y)

    if debug:
        print((1-stats.norm.cdf(z_value_x))*2, (1-stats.norm.cdf(z_value_y))*2)

    #-1 indicates strong confidence that we have a.com, +1 indicates strong confidence that we resumed b.com, 0 means we don't know cause it either doesn't match any or both
    confidence = (1-stats.norm.cdf(z_value_y))*2-(1-stats.norm.cdf(z_value_x))*2
    return confidence

def main(collection_name=None):
    global proc_pool
    target_sim = "similarity_levenshtein"

    ScanContext.initialize(mongo_collection_name=collection_name)
    start = time.time()
    res = ScanContext.neo4j.session().run("""
            MATCH (I)-[IR: SIM { first_color: "WHITE" }]-(R:REDIRECT_HTML)
            WHERE IR[$sim_typ]<2
            WITH I, IR, R,
                COLLECT { 
                    MATCH (a)-[A:SIM]-(I)
                    WHERE a.domain = I.domain
                    AND A[$sim_typ] IS NOT NULL
                    RETURN[a, A]
                    ORDER BY A[$sim_typ] DESC
                } as other_a,
                COLLECT {
                    MATCH (I)-[B: SIM]-(b)
                    WHERE B[$sim_typ] IS NOT NULL
                    AND b.domain <> I.domain
                    RETURN[b, B]
                    ORDER BY B[$sim_typ] DESC
                } as a_b
            RETURN I, IR, R, other_a, a_b
            LIMIT 10000""", { "sim_typ":  target_sim}, routing_=RoutingControl.READ)
    print("Took ", time.time()-start)
    max_confidence_value_pairs = {}
    for r in res:
        #print(r.get("I"))
        #print(r.get("IR"))
        #print(r.get("R"))
        #print()
        #for x in r.get("other_a"):
        #    print(x[0].get("domain"), x[1].get(target_sim))
        samesitesimilarities = [x[1].get(target_sim) for x in r.get("other_a")]
        #print()
        othersitesimilaritiesdict  = {}
        for x in r.get("a_b"):
            domain = x[0].get("domain")
            if domain not in othersitesimilaritiesdict:
                othersitesimilaritiesdict[domain] = []
            othersitesimilaritiesdict[domain].append(x[1].get(target_sim))

        #    print(x[0].get("domain"), x[1].get(target_sim))
        #othersitesimilarities = [x[1].get(target_sim) for x in r.get("a_b")]
        resumtionsimilarity = r.get("IR").get(target_sim)
        #print(samesitesimilarities)
        #print(othersitesimilarities)
        #print(resumtionsimilarity)
        confidence_values = []
        for k,v in othersitesimilaritiesdict.items():
            if resumtionsimilarity is None: continue
            confidence = calculate_confidence(np.array(samesitesimilarities), np.array(v), resumtionsimilarity, debug=False)
            confidence_values.append((confidence, k))
        if len(confidence_values) > 0:
            max_confidence = max(confidence_values, key=lambda k : k[0])
            if max_confidence[0]>0.9:        
                print("Domain", r.get("I").get("domain"), "most likely resumes to", max_confidence[1] ,"with confidence", max_confidence[0])
                print("\n\n")
            max_confidence_value_pairs[max_confidence[1]] = max_confidence[0]
    
    plt.hist(list(max_confidence_value_pairs.values()), bins=200)
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.yscale('log')
    plt.savefig('hist.png')

def test(collection_name=None):
    global proc_pool
    target_sim = "similarity_levenshtein"

    ScanContext.initialize(mongo_collection_name=collection_name)
    start = time.time()
    res = ScanContext.neo4j.session().run("""
            MATCH (I)-[IR: SIM { first_color: "WHITE" }]-(R:REDIRECT_HTML)
                WITH I, IR, R,
                    COLLECT {
                        MATCH (R)-[B: SIM]-(b)
                        WHERE I.domain <> b.domain
                        AND B[$sim_typ] > 0.9
                        RETURN[b, B]
                        ORDER BY B[$sim_typ] DESC
                        LIMIT 1
                    } as other_b
                WHERE size(other_b) > 0
                AND other_b[0][0].domain = "www.billionaireapk.com"
                RETURN I, IR, R, other_b
                """, { "sim_typ":  target_sim}, routing_=RoutingControl.READ)
    i = 0
    for r in res:
        print(r.get("R").get("domain"))
        i+=1
    print(i)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s | %(process)d %(processName)s - %(name)s.%(funcName)s: %(message)s",
        stream=sys.stdout,
    )
    logging.getLogger("neo4j").setLevel(logging.WARNING)
    logging.getLogger("pymongo").setLevel(logging.WARNING)
    try:
        test("ticket_redirection_2024-08-19_19:28")
    except:
        LOGGER.exception("Error in main")
        raise
