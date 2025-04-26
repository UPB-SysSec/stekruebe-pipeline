import logging
import itertools
import os
import warnings
import time

from bson import ObjectId
from neo4j import Driver as Neo4jDriver, EagerResult
from pymongo.collection import Collection
from utils.db import MongoCollection, MongoDB, Neo4j, connect_mongo, connect_neo4j, get_most_recent_collection_name
from utils.asn import lookup as lookup_asn
from tqdm import tqdm
from multiprocessing import Pool
from multiprocessing.pool import ThreadPool
from utils.cdnaddresses import *
from collections import defaultdict

warnings.filterwarnings("ignore", "Degrees of freedom <= 0 for slice")
warnings.filterwarnings("ignore", "invalid value encountered in scalar divide")

LOGGER = logging.getLogger(__name__)
CONFIDENCE_VERSION = 2


class ScanContext:
    neo4j: Neo4jDriver = None
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



def get_body(doc_id, resumption_idx=None):
    doc = ScanContext.mongo_collection.find_one(ObjectId(doc_id))
    if resumption_idx == None:
        zgrab_output = doc.get("initial")
    else:
        zgrab_output = doc.get("redirect")[resumption_idx]
    return zgrab_output.get("data").get("http").get("result").get("response").get("body")

def ip_to_asn(ip):
    asn = lookup_asn(ip)
    if asn is not None:
        return asn

def ip_to_cdn(ip1, ip2):
    if is_akamai_ip(ip1) or is_akamai_ip(ip2):
        return "akamai"
    elif is_cloudflare_ip(ip1) or is_cloudflare_ip(ip2):
        return "cloudflare"
    elif is_fastly_ip(ip1) or is_fastly_ip(ip2):
        return "fastly"
    elif is_google_ip(ip1) or is_google_ip(ip2):
        return "google"
    elif is_amazon_ip(ip1) or is_amazon_ip(ip2):
        return "amazon"
    else:
        asn1 = ip_to_asn(ip1)
        asn2 = ip_to_asn(ip2)
        if asn1 == asn2 and asn1 is not None:
            return str(asn1)
        return f"{asn1} to {asn2}"



def dump_row(row):
    initial_node = row.get("I")
    resumption_node = row.get("R")
    srcip = initial_node.get("ip")
    dstip = resumption_node.get("ip")
    cdn_name = ip_to_cdn(srcip, dstip)
    target_path = f"analysisdump_unsafe/{cdn_name}/{dstip}/{srcip}"
    initial_resumption_relation = row.get("IR")
    
    initial = get_body(ObjectId(initial_node.get("doc_id")))
    assert initial_node.get("doc_id") == resumption_node.get("doc_id")
    if resumption_node["redirect_index"] is None:
        print(resumption_node)
    resumed = get_body(
        ObjectId(resumption_node.get("doc_id")),
        int(resumption_node["redirect_index"])
    )

    os.makedirs(target_path, exist_ok=True)


    with open(f"{target_path}/_meta.md", "a") as fm:
        initial_node_domain = initial_node.get("domain")
        fm.write(f"# {initial_node_domain}: {srcip} -> {dstip}\n")
        fm.write(f"Domain was: {initial_node_domain}\n")
        reason = initial_resumption_relation.get("c_reason")
        fm.write(f"Reason: {reason}\n\n")

        with open(f"{target_path}/0_initial.html", "w") as f:
            f.write(str(initial))
        with open(f"{target_path}/1_resumed.html", "w") as f:
            f.write(str(resumed))


def main():
    ScanContext.initialize(mongo_collection_name="ticket_redirection_2024-12-13_17:41")

    i = 0
    with ScanContext.neo4j.session() as session:
        res = session.run(
            f"""
        MATCH (I)-[IR: RESUMED_AT {{classification: "UNSAFE"}}]-(R: REDIRECT_HTML)
        RETURN I,IR, R
        """
        )
        for x in res:
            dump_row(x)
            i += 1
    print("Dumped", i, "rows")
        

if __name__ == "__main__":
    start = time.time()
    main()
    print("DONE in", time.time() - start, "seconds")
