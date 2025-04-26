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


SIMILARITIES = (
    "levenshtein",
    "levenshtein_header",
#    "radoy_header",
#    "bag_of_paths",
)


def create_indexes():
    for sim in SIMILARITIES:
        print(f"Creating index for {sim}")
        ScanContext.neo4j.execute_query(
            f"CREATE INDEX sim_color_{sim} IF NOT EXISTS FOR ()-[r:SIM]-() ON (r.first_color, r.similarity_{sim});"
        )


def wait_for_index(target_sim):
    while True:
        res: EagerResult = ScanContext.neo4j.execute_query(
            f"SHOW INDEXES WHERE labelsOrTypes=['SIM'] and properties=['first_color', 'similarity_{target_sim}'];"
        )
        if len(res.records) == 0:
            create_indexes()
            continue
        if res.records[0]["state"] == "ONLINE":
            break
        print("Waiting for index to be ONLINE: ", res.records[0]["state"], res.records[0]["populationPercent"])
        time.sleep(30)

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


def matches_known_good_pattern(doc):
    if doc is None:
        return False

    # Edgesuite Standard Error
    if doc.startswith(
        '<HTML><HEAD>\n<TITLE>Invalid URL</TITLE>\n</HEAD><BODY>\n<H1>Invalid URL</H1>\nThe requested URL "&#91;no&#32;URL&#93;", is invalid.<p>\nReference'
    ):
        return True

    # Edgesuite Standard Error
    if doc.startswith(
        "<HTML><HEAD><TITLE>Error</TITLE></HEAD><BODY>\nAn error occurred while processing your request.<p>\nReference"
    ):
        return True

    # Akamai Request Reject
    if doc.startswith(
        "<html><head><title>Request Rejected</title></head><body>The requested URL was rejected. Please consult with your administrator.<br><br>Your support ID is: "
    ):
        return True
    
    # Google misrouting
    if doc.startswith("response 404 (backend NotFound), service rules for the path non-existent"):
        return True

    # Fastly fix
    if doc.startswith("Requested host does not match any Subject Alternative Names (SANs) on TLS certificate "):
        return True

total_by_as = defaultdict(list)
total_by_cdn = defaultdict(list)
CF = 0
def dump_row(target_sim, row):
    initial_node = row.get("I")
    resumption_node = row.get("R")
    assumed_origin_node = row.get("O")
    srcip = initial_node.get("ip")
    dstip = resumption_node.get("ip")
    cdn_name = ip_to_cdn(srcip, dstip)
    target_path = f"analysisdump/{cdn_name}/{dstip}/{srcip}"
    initial_resumption_relation = row.get("IR")
    resumption_origin_relation = row.get("RO")
    
    initial = get_body(ObjectId(initial_node.get("doc_id")))
    assert initial_node.get("doc_id") == resumption_node.get("doc_id")
    resumed = get_body(
        ObjectId(resumption_node.get("doc_id")),
        int(resumption_node["redirect_index"])
    )
    total_by_cdn[cdn_name].append(f"{srcip}->{dstip}")
    total_by_as[f"{ip_to_asn(srcip)} to {ip_to_asn(dstip)}"].append(f"{srcip}->{dstip}")

    
    return

    if matches_known_good_pattern(resumed):
        return

    os.makedirs(target_path, exist_ok=True)

    sim_IR = initial_resumption_relation.get(f"similarity_{target_sim}")
    sim_OR = resumption_origin_relation.get(f"similarity_{target_sim}")

    with open(f"{target_path}/_{target_sim[:2]}_{sim_IR:.2f}_{sim_OR:.2f}", "w") as f:
        pass

    with open(f"{target_path}/_meta.md", "a") as fm:
        initial_node_domain = initial_node.get("domain")
        fm.write(f"# {initial_node_domain}: {srcip} -> {dstip}\n\n")

        with open(f"{target_path}/0_initial.html", "w") as f:
            f.write(str(initial))
        with open(f"{target_path}/1_resumed.html", "w") as f:
            f.write(str(resumed))

        fm.write(f"# {target_sim}\n")
        fm.write(f"Initial to Resumption Similarity: {sim_IR:5.3f}\n")

        fm.write(f"Resumption to Origin Similarity: {sim_OR:5.3f}\n")

        dstdomain = assumed_origin_node.get("domain")
        fm.write(f"Domain : {dstdomain}\n\n")

        body = get_body(ObjectId(assumed_origin_node.get("doc_id")))
        with open(f"{target_path}/2_{target_sim}_supposed_origin.html", "w") as f:
            f.write(str(body))



def main():
    ScanContext.initialize(mongo_collection_name="ticket_redirection_2024-12-13_17:41")

    cutoff_IR, cutoff_OR = 0.6, 0.9

    for sim in SIMILARITIES:
        i = 0
        wait_for_index(sim)
        with ScanContext.neo4j.session() as session:
            res = session.run(
                f"""
            MATCH (I)-[IR:SIM {{first_color: "WHITE"}}]-(R: REDIRECT_HTML)
            WHERE  IR.similarity_{sim} >= 0 AND IR.similarity_{sim} <= {cutoff_IR}
            WITH I,IR,R, COLLECT {{
                MATCH (R)-[RO:SIM]-(O)
                WHERE RO.similarity_{sim} >= {cutoff_OR}
                AND O.domain <> I.domain
                AND O.cert_fingerprint <> I.cert_fingerprint
                RETURN [RO, O]
                ORDER BY RO.similarity_{sim} DESC
                LIMIT 1
            }} as others
            WHERE size(others) > 0
            RETURN I,R,others[0][1] as O,IR,others[0][0] as RO
            """
            )
            for row in res:
                dump_row(sim, row)
                i+=1
            global CF
            print(i, "rows dumped for", sim, "of which" , CF, "are cloudflare")
            CF = 0
    def dict_to_out(x):
        for k, v in x.items():
            print(k,";", len(set(v)))
    dict_to_out(total_by_as)
    dict_to_out(total_by_cdn)
        

if __name__ == "__main__":
    start = time.time()
    main()
    print("DONE in", time.time() - start, "seconds")
