import logging
import itertools
import warnings
import time

from neo4j import Driver as Neo4jDriver, EagerResult
from pymongo.collection import Collection
from utils.db import MongoCollection, MongoDB, Neo4j, connect_mongo, connect_neo4j, get_most_recent_collection_name
from utils.asn import lookup as lookup_asn
from tqdm import tqdm
from multiprocessing import Pool
from multiprocessing.pool import ThreadPool

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


SIMILARITIES = (
    "levenshtein",
    "levenshtein_header",
    "radoy_header",
    "bag_of_paths",
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


def look_at(target_sim, cutoff_IR, cutoff_OR):
    wait_for_index(target_sim)
    with ScanContext.neo4j.session() as session:
        res = session.run(
            f"""
        MATCH (I)-[IR:SIM {{first_color: "WHITE"}}]-(R: REDIRECT_HTML)
        WHERE  IR.similarity_{target_sim} >= 0 AND IR.similarity_{target_sim} <= {cutoff_IR}
        AND EXISTS {{
            MATCH (R)-[RO:SIM]-(O)
            WHERE RO.similarity_{target_sim} >= {cutoff_OR}
                AND O.domain <> I.domain
                AND O.cert_fingerprint <> I.cert_fingerprint
        }}
        RETURN COUNT(IR)
        """
        )
        return res.single().value()


def main():
    ScanContext.initialize()

    PARAMS = [
        (0.01, 1),
        (0.01, 0.99),
        (0.05, 0.95),
        (0.1, 0.9),
        (0.2, 0.8),
        (0.3, 1),
        (0.4, 0.9),
        (0.5, 0.8),
    ]

    TABLE: map[str, map[tuple[float, float], int]] = {}

    with Pool() as pool:
        _PARAMS = list(itertools.product(SIMILARITIES, [p[0] for p in PARAMS], [p[1] for p in PARAMS]))
        for p_, r in zip(_PARAMS, pool.starmap(look_at, _PARAMS)):
            sim = p_[0]
            p = (p_[1], p_[2])
            TABLE.setdefault(sim, {})[p] = r
            print(".", end="", flush=True)
    print()

    LONGEST_METRIC_NAME = max(len(sim) for sim in SIMILARITIES)

    print("| ", end="")
    print(" " * LONGEST_METRIC_NAME, end=" | ")
    for p in PARAMS:
        formatted = f"{p[0]:.2f}/{p[1]:.2f}"
        print(formatted, end=" | ")
    print()

    print("| ", end="")
    print(":", "-" * (LONGEST_METRIC_NAME - 1), end=" | ", sep="")
    for p in PARAMS:
        print("--------:", end=" | ")
    print()

    for sim in SIMILARITIES:
        print("| ", end="")
        print(sim.ljust(LONGEST_METRIC_NAME), end=" | ")
        for p in PARAMS:
            print(f"{TABLE[sim][p]:9d}", end=" | ")
        print()


if __name__ == "__main__":
    start = time.time()
    main()
    print("DONE in", time.time() - start, "seconds")
