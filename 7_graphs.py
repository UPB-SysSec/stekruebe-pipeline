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
from joblib import Parallel, delayed
import math
from ipaddress import *
from collections import defaultdict

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


#CREATE INDEX levconf FOR ()-[r:SIM]-() ON (r.similarity_levenshtein_maxconf_val)

def draw_hist(data, filename):
    plt.hist(data, bins=200)
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.yscale('log')
    plt.savefig("figures/"+filename)
    plt.clf()
    plt.cla()
    plt.close()

def create_complete_histogram(target_sim):
    target_conf = target_sim+"_maxconf_val"
    res = ScanContext.neo4j.session().run("""
            MATCH ()-[IR:SIM]->()
            USING INDEX IR:SIM("""+target_conf+""")
            WHERE IR."""+target_conf+""" is not NULL
            RETURN IR."""+target_conf+""" AS confval
            """, target_conf=target_conf, routing_=RoutingControl.READ)
    sims = [x.get("confval") for x in res]
    draw_hist(sims, "hist_"+target_sim+".png")
    

def is_network_ip(ip, v4network, v6network):
    #TODO better do regex magic
    if "." in ip:
        ip = IPv4Address(ip)
        network = v4network
    else:
        ip = IPv6Address(ip)
        network = v6network
    for x in network:
        if ip in x: return True
    return False

#https://www.cloudflare.com/ips/ Accessed: 2024-12-13
cloudflare_network_v4 = [IPv4Network(x) for x in ["173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22","141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20","197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13","104.24.0.0/14","172.64.0.0/13","131.0.72.0/22"]]
cloudflare_network_v6 = [IPv6Network(x) for x in ["2400:cb00::/32","2606:4700::/32","2803:f800::/32","2405:b500::/32","2405:8100::/32","2a06:98c0::/29","2c0f:f248::/32"]]

def is_cloudflare_ip(ip):
    return is_network_ip(ip, cloudflare_network_v4, cloudflare_network_v6)

#https://www.fastly.com/documentation/reference/api/utils/public-ip-list/ Accessed: 2024-12-13
fastly_network_v4 = [IPv4Network(x) for x in ["23.235.32.0/20","43.249.72.0/22","103.244.50.0/24","103.245.222.0/23","103.245.224.0/24","104.156.80.0/20","140.248.64.0/18","140.248.128.0/17","146.75.0.0/17","151.101.0.0/16","157.52.64.0/18","167.82.0.0/17","167.82.128.0/20","167.82.160.0/20","167.82.224.0/20","172.111.64.0/18","185.31.16.0/22","199.27.72.0/21","199.232.0.0/16"]]
fastly_network_v6 = [IPv6Network(x) for x in ["2a04:4e40::/32","2a04:4e42::/32"]]

def is_fastly_ip(ip):
    return is_network_ip(ip, fastly_network_v4, fastly_network_v6)

#File from https://github.com/SecOps-Institute/Akamai-ASN-and-IPs-List/blob/master/akamai_ip_cidr_blocks_raw.lst, Replace if you find anything better. Downloaded: 2024-12-13
with open("akamai_ip_cidr_blocks_raw.lst") as f:
    akamai_network_v4 = [IPv4Network(x.rstrip()) for x in f.readlines()]
def is_akamai_ip(ip):
    is_network_ip(ip, akamai_network_v4, [])

def create_network_histogram(target_sim, network_name, network_ip_function):
    target_conf = target_sim+"_maxconf_val"
    res = ScanContext.neo4j.session().run("""
            MATCH (x)-[IR:SIM]->(y)
            USING INDEX IR:SIM("""+target_conf+""")
            WHERE IR."""+target_conf+""" is not NULL
            RETURN IR."""+target_conf+"""  AS confval, x.ip as ip1, y.ip as ip2
            """, target_conf=target_sim+"_maxconf_val", routing_=RoutingControl.READ)
    sims = [x.get("confval") for x in res if network_ip_function(x.get("ip1")) or network_ip_function(x.get("ip2"))]
    
    draw_hist(sims, "cdn_"+network_name+"_"+target_sim+".png")

def create_cloudflare_histogram(target_sim):
    create_network_histogram(target_sim, "cloudflare", is_cloudflare_ip)

def create_fastly_histogram(target_sim):
    create_network_histogram(target_sim, "fastly", is_fastly_ip)

def create_akamai_histogram(target_sim):
    create_network_histogram(target_sim, "akamai", is_akamai_ip)

def main(collection_name=None):
    ScanContext.initialize(mongo_collection_name=collection_name)
    start = time.time()

    target_sims = ["similarity_levenshtein", "similarity_levenshtein_header", "similarity_bag_of_paths", "similarity_radoy_header"]
    for target_sim in target_sims:
        LOGGER.info("Creating Index (if not exists)")
        ScanContext.neo4j.execute_query("CREATE INDEX "+target_sim+"_conf IF NOT EXISTS FOR ()-[r:SIM]-() ON (r."+target_sim+"_maxconf_val)")
        LOGGER.info("Creating complete histogram")
        create_complete_histogram(target_sim)
        LOGGER.info("Creating cloudflare histogram")
        create_cloudflare_histogram(target_sim)
        LOGGER.info("Creating fastly histogram")
        #No fastly data in set
        create_fastly_histogram(target_sim)
        LOGGER.info("Creating akamai histogram")
        #No akamai data in set
        create_akamai_histogram(target_sim)

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
