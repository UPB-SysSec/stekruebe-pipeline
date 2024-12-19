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
import math

from collections import defaultdict


from collections import Counter
import os
from time import sleep


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

        #mongodb = connect_mongo(verify_connectivity=verify_connectivity)
        #database = mongodb["steckruebe"]
        #if not mongo_collection_name:
        #    mongo_collection_name = get_most_recent_collection_name(database, "ticket_redirection_")
        #    logging.info(f"Using most recent collection: {mongo_collection_name}")
        #if not mongo_collection_name:
        #    raise ValueError("Could not determine most recent collection")
        #ScanContext.mongo_collection = database[mongo_collection_name]


def write_transaction(tx, rel_id, metric, domainname, confidence):
    query = """
    MATCH ()-[r]->()
    WHERE elementId(r) = $rel_id
    SET r[$property_name_1] = $property_value_1
    SET r[$property_name_2] = $property_value_2
    """
    if confidence > 2:
        print(domainname)
    tx.run(query, rel_id=rel_id, property_name_1=metric+"_maxconf_domain", property_value_1=domainname, property_name_2=metric+"_maxconf_val", property_value_2=confidence)

def calculate_confidence(r, target_sim):
    target_relationship = r.get("IR")
    resumtionsimilarity = target_relationship.get(target_sim)
    if resumtionsimilarity is None: return
    samesitesimilarities = np.array(r.get("other_a"))

    if len(samesitesimilarities) == 0:
            maximum_confidence = ("-", 0.0)
    else:
        mean_x = np.mean(samesitesimilarities)
        error_x = (np.std(samesitesimilarities, ddof=1, mean=mean_x) / np.sqrt(len(samesitesimilarities)-1)) or 1e-12
        z_value_x = abs((resumtionsimilarity - mean_x) /error_x)
        cdf_x = stats.norm.sf(z_value_x)

        def __do(y):
            n = len(y)
            if n < 2:
                return 0.0
            mean_y = np.mean(y)
            #error_y_1 = stats.sem(y, nan_policy='propagate') or 1e-12
            #Mathematical hack so things go wooosh
            error_y = (np.std(y, ddof=1, mean=mean_y) / np.sqrt(n-1)) or 1e-12
            z_value_y = abs((resumtionsimilarity - mean_y) /error_y)
            cdf_y = stats.norm.sf(z_value_y)
            return (cdf_y* 2) - (cdf_x* 2) 


        #-1 indicates strong confidence that we have a.com, +1 indicates strong confidence that we resumed b.com, 0 means we don't know cause it either doesn't match any or both
        #ab = itertools.groupby(r.get("a_b"), lambda x : x[0])
        abc = defaultdict(list)
        for x in r.get("a_b"): abc[x[0]].append(x[1])
        if len(abc) > 0: 
            confidence_per_domain = [(k, __do(np.array(v))) for k,v in abc.items()]
            maximum_confidence = max(confidence_per_domain, key=lambda x : x[1])
        else:
            maximum_confidence = ("-", 0.0)
        #confidence_per_domain.sort(key=lambda x:x[1], reverse=True)

    try:
        ScanContext.neo4j.session().execute_write(
            write_transaction,
            rel_id=r.get("id"),
            metric=target_sim,
            domainname=maximum_confidence[0],
            confidence=float(maximum_confidence[1]))
    except Exception as e:
        print("Ex", e, type(e))
    

    """
            MATCH (I)-[IR: SIM { first_color: "WHITE" }]-()
            WITH I, IR,
                COLLECT { 
                    MATCH (a)-[A:SIM]-(I)
                    WHERE a.domain = I.domain
                    AND A[$sim_typ] IS NOT NULL
                    RETURN A[$sim_typ]
                } as other_a,
                COLLECT {
                    MATCH (I)-[B: SIM]-(b)
                    WHERE b.domain <> I.domain
                    AND B[$sim_typ] IS NOT NULL
                    RETURN [b.domain, B[$sim_typ]]
                } as a_b
            RETURN elementId(IR) as id, IR, other_a, a_b
            LIMIT 10000
            """

def calculate(collection_name, target_sim):
    ScanContext.initialize(mongo_collection_name=collection_name)
    i = 1
    while i > 0:
        #TODO: THIS CRASHES FOR VALUES >100000 DUE TO OUT OF MEM
        res = ScanContext.neo4j.session().run("""
                MATCH (I)-[IR: SIM { first_color: "WHITE" }]->()
                WHERE IR[$conf_typ] is NULL
                WITH I, IR,
                    COLLECT { 
                        MATCH (a:HTML)-[A:SIM]-(I)
                        USING INDEX a:HTML (domain)
                        WHERE a.domain = I.domain
                        RETURN A[$sim_typ]
                    } as other_a,
                    COLLECT {
                        MATCH (I)-[B: SIM]-(b)
                        WHERE b.domain <> I.domain
                        RETURN b.domain, B
                    } as a_b
                LIMIT 100
                RETURN elementId(IR) as id, IR, other_a, a_b
                """, { "sim_typ":  target_sim, "conf_typ": target_sim+"_maxconf_val"}, routing_=RoutingControl.READ)
        #Somehow doesnt work with multiprocessing
        #with ProcessPoolExecutor() as executor:
        #    executor.map(lambda r: calculate_confidence(r, target_sim), res)
        i = 0
        for r in res:
            i+=1
            calculate_confidence(r, target_sim)

def main(collection_name=None):
    #target_sims = ["similarity_levenshtein", "similarity_levenshtein_header", "similarity_bag_of_paths", "similarity_radoy_header"]
    start = time.time()

    calculate(collection_name)

    print(time.time() - start)
    
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s | %(process)d %(processName)s - %(name)s.%(funcName)s: %(message)s",
        stream=sys.stdout,
    )
    logging.getLogger("neo4j").setLevel(logging.WARNING)
    logging.getLogger("pymongo").setLevel(logging.WARNING)
    try:
        main("ticket_redirection_2024-08-19_19:28")
    except:
        LOGGER.exception("Error in main")
        raise
