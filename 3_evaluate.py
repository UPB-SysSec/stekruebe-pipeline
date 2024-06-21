import logging
from pprint import pprint
from neo4j import GraphDatabase
from pymongo import MongoClient
from enum import Enum
from dataclasses import dataclass
from typing import Union, Optional
from utils.credentials import mongodb_creds, neo4j_creds
from utils.result import Zgrab2ResumptionResult
import Levenshtein
from multiprocessing.pool import ThreadPool
from multiprocessing.pool import Pool as ProcessPool
import os
import time
import datetime
import functools
import sys


# @functools.lru_cache(maxsize=1024 * 1024 * 10)
@functools.wraps(Levenshtein.ratio)
def levenstein_ratio(a, b):
    return Levenshtein.ratio(a, b)


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
            self.certificate = self._handshake_log["server_certificates"]["certificate"]["raw"]
            self.parsed_certificate = self._handshake_log["server_certificates"]["certificate"].get("parsed")
        self.status_code = self._response.get("status_code", -1)
        self.body_sha256 = self._response.get("body_sha256", None)
        self.body = self._response.get("body", None)
        self.body_len = self._response.get("body_len", None)
        self.content_title = self._response.get("content_title", None)
        self.content_length = self._response.get("content_length", None)
        self.location = self._response.get("headers", {}).get("location", [])
        assert len(self.location) < 2
        self.location = self.location[0] if self.location else None

        # filter location
        if self.location and self.location.startswith("/sttc/px/captcha-v2/index.html?url=Lz8"):
            self.location = "/sttc/px/captcha-v2/index.html?url=Lz8"

    def __str__(self) -> str:
        sha_format = f"{self.body_sha256:.6s}" if self.body_sha256 else "None"
        return f"Response(status_code={self.status_code!r}, body_sha256={sha_format}, content_title={self.content_title!r:.50}, content_length={self.content_length!r}, body_len={self.body_len!r}, location={self.location!r})"

    def __repr__(self) -> str:
        return f"Response(status_code={self.status_code!r}, body_sha256={self.body_sha256!r}, content_title={self.content_title!r:.50}, content_length={self.content_length!r}, body_len={self.body_len!r}, location={self.location!r})"


class ResumptionClassificationType(Enum):
    NOT_APPLICABLE = 0
    SAFE = 1
    UNSAFE = 2

    @staticmethod
    def from_bool_is_safe(is_safe):
        return ResumptionClassificationType.SAFE if is_safe else ResumptionClassificationType.UNSAFE

    @property
    def is_safe(self):
        return self.value <= ResumptionClassificationType.SAFE.value


@dataclass
class ResumptionClassification:
    classification: ResumptionClassificationType
    reason: str
    value_initial: Optional[str]
    value_redirect: Optional[str]

    def __init__(
        self,
        is_safe: Union[ResumptionClassificationType, bool],
        reason: str,
        reason_initial: Optional[str] = None,
        reason_redirect: Optional[str] = None,
    ):
        if isinstance(is_safe, bool):
            self.classification = ResumptionClassificationType.from_bool_is_safe(is_safe)
        else:
            self.classification = is_safe
        self.reason = reason
        self.value_initial = reason_initial
        self.value_redirect = reason_redirect

    @property
    def is_safe(self):
        return self.classification.is_safe

    @staticmethod
    def safe(reason):
        return ResumptionClassification(ResumptionClassificationType.SAFE, reason)

    @staticmethod
    def not_applicable(reason):
        return ResumptionClassification(ResumptionClassificationType.NOT_APPLICABLE, reason)

    @staticmethod
    def unsafe(reason, a=None, b=None):
        return ResumptionClassification(ResumptionClassificationType.UNSAFE, reason, a, b)

    @staticmethod
    def assert_equal(a, b, reason):
        return ResumptionClassification(a == b, reason, a, b)


class _ProcessLocal:
    _pid = None

    def __init__(self):
        raise Exception("Class not instanced")

    @classmethod
    def is_same_pid(cls):
        return cls._pid == os.getpid()

    @classmethod
    def store_pid(cls):
        cls._pid = os.getpid()


# Process local singleton for Neo4J Access
class Neo4JDatabase(_ProcessLocal):
    db_driver = None
    _conneciton_uri = None
    _connection_auth = None

    @classmethod
    def get_connection(cls, uri=..., auth=...):
        if not cls.is_same_pid() or cls.db_driver is None:
            cls.store_pid()
            if uri is not ...:
                logging.debug(f"Storing uri")
                cls._conneciton_uri = uri
            if auth is not ...:
                logging.debug(f"Storing auth")
                cls._connection_auth = auth
            logging.debug(f"Connecting to Neo4J at {cls._conneciton_uri}")
            cls.db_driver = GraphDatabase.driver(cls._conneciton_uri, auth=cls._connection_auth)
        return cls.db_driver


def remove_password(uri: str):
    import urllib.parse

    parsed = urllib.parse.urlparse(uri)
    if parsed.password:
        parsed = parsed._replace(netloc="{}:{}@{}".format(parsed.username, "***", parsed.hostname))
    return parsed.geturl()


# Process local for MongoDB Access
class MongoCollection(_ProcessLocal):
    db_driver = None
    collection = None
    _connection_uri = None
    _connection_kwargs = None
    _collection_database = None
    _collection_name = None

    def __init__(self):
        raise Exception("Class not instanced")

    @classmethod
    def get_connection(cls, uri=..., **kwargs):
        if not cls.is_same_pid() or cls.db_driver is None:
            cls.store_pid()
            if uri is not ...:
                logging.debug(f"Storing uri and kwargs")
                cls._connection_uri = uri
                cls._connection_kwargs = kwargs
            logging.debug(f"Connecting to MongoDB at {remove_password(cls._connection_uri)}")
            if not cls._connection_uri:
                raise Exception("No URI set")
            cls.db_driver = MongoClient(cls._connection_uri, **cls._connection_kwargs)
        return cls.db_driver

    @classmethod
    def get_collection(cls, database=..., collection=...):
        if not cls.is_same_pid() or not cls.collection or collection:
            if database is not ...:
                cls._collection_database = database
            if collection is not ...:
                cls._collection_name = collection
            cls.collection = cls.get_connection()[cls._collection_database][cls._collection_name]
        return cls.collection


def extract_subjects(parsed_cert):
    subjects = []
    if not parsed_cert:
        return subjects
    try:
        subjects.extend(parsed_cert["subject"]["common_name"])
    except KeyError:
        pass
    try:
        subjects.extend(parsed_cert["extensions"]["subject_alt_name"]["dns_names"])
    except KeyError:
        pass
    # get rid of wildcards and add www. if not present
    subjects = [s.lstrip("*.") for s in subjects]
    subjects = subjects + [f"www.{s}" for s in subjects if not s.startswith("www.")]
    return list(set(subjects))


def classify_resumption(initial: Response, resumption: Response, domain_from: str):
    # TODO maybe classify multiple resumptions at once
    if not resumption.resumed:
        return ResumptionClassification.safe("no resumption")
    # initial was error - ignore
    if initial.status_code < 0:
        return ResumptionClassification.not_applicable("initial was complete error")
    if resumption.status_code < 0:
        return ResumptionClassification.not_applicable("redirect was complete error")
    if initial.status_code > 400:
        return ResumptionClassification.not_applicable("initial was error")

    if resumption.status_code == 403:
        return ResumptionClassification.not_applicable("resumption got 403")
    if resumption.status_code == 421:
        return ResumptionClassification.safe("resumption got 421 - redirection was detected")
    if resumption.status_code == 429:
        return ResumptionClassification.not_applicable("resumption got 429 - they blocked us :(")
    if resumption.status_code == 502:
        return ResumptionClassification.not_applicable("resumption got 502 - not routed")
    if resumption.status_code == 525:
        # 525 SSL handshake failed
        # (via https???)
        return ResumptionClassification.not_applicable("resumption got 525 - failed on HTTP layer")

    # initially we were redirected ...
    if initial.status_code in range(300, 400):
        assert initial.location
        if resumption.status_code in range(300, 400):
            assert resumption.location
            # ... on resumption as well - was the location the same?
            return ResumptionClassification.assert_equal(initial.location, resumption.location, "location")
        # ... but not on resumption - which means the server is handling us differently
        return ResumptionClassification.unsafe(
            "initial was redirect, resumption was not",
            initial.status_code,
            resumption.status_code,
        )

    # if resumption 300 and initial 200 check redirect to original
    if resumption.status_code in range(300, 400):
        assert resumption.location
        if resumption.location in [f"https://{domain_from}"] or resumption.location.startswith(
            f"https://{domain_from}/"
        ):
            return ResumptionClassification.safe("redirect to original")
        else:
            return ResumptionClassification.unsafe("redirect to different", domain_from, resumption.location)

    if initial.body_sha256 is not None and initial.body_sha256 == resumption.body_sha256:
        # same content
        return ResumptionClassification.safe("body sha256")

    # if initial.content_title is not None and resumption.content_title is not None:
    #     # same title -> probably same content
    #     # TODO: maybe remove this?
    #     return ResumptionClassification.assert_equal(initial.content_title, resumption.content_title, "title")

    _LEVENSHTEIN_THRESHOLD = 0.5

    # compare initial and resumption body by levenshtein
    max_r = levenstein_ratio(initial.body, resumption.body)
    closest_body, closest_cert = initial.body, initial.certificate
    max_r_is_initial = True

    # check all neighbors for levenshtein match - give us the thing we are most likely on
    # neighbor_domains = get_domain_neighborhood(domain_from)
    # TODO: store all computed ratios - then store the ratios of the closest match with the same cert and the closest match with a different cert
    relevant_domains = get_domains_on_ip(resumption._ip) + extract_subjects(initial.parsed_certificate)
    for n in relevant_domains:
        for neighbor_body, neighbor_cert in unique(get_domain_body_and_cert(n)):
            r = levenstein_ratio(resumption.body, neighbor_body)
            if r > max_r:
                closest_body, closest_cert = neighbor_body, neighbor_cert
                max_r = r
                max_r_is_initial = False

    # we actually consider this sufficiently close
    if max_r > _LEVENSHTEIN_THRESHOLD:
        assert type(closest_cert) == str
        assert type(initial.certificate) == str
        if max_r_is_initial:
            return ResumptionClassification.safe("levenshtein: matched initial")

        if closest_cert != initial.certificate:
            return ResumptionClassification.unsafe("levenshtein: strongly matching neighbor with different cert")
        else:
            return ResumptionClassification.safe("levenshtein: neighbor with same cert")

    # if initial.body and resumption.body:
    #     if Levenshtein.ratio(initial.body, resumption.body) > _LEVENSHTEIN_THRESHOLD:
    #         return ResumptionClassification.safe("body by levenshtein")
    #     else:
    #         return ResumptionClassification.unsafe("body by levenshtein")
    # only one of initial/resumption has a title - does the status code change?
    # if initial.content_title is not None and resumption.content_title is None:
    #     return ResumptionClassification.assert_equal(
    #         initial.status_code,
    #         resumption.status_code,
    #         "compare statuscode when redirected from content to title-less with different statuscode",
    #     )
    # if initial.content_title is None and resumption.content_title is not None:
    #     return ResumptionClassification.assert_equal(
    #         initial.status_code,
    #         resumption.status_code,
    #         "compare statuscode when redirected from title-less to content with different statuscode",
    #     )

    # WE DO NOT HAVE ANY CONTENT TITLE TO GO OFF OF

    # status code changed from okayish to error or the other way around -> thats clearly suspicious
    # if initial.status_code in range(200, 300) and resumption.status_code in range(
    #     400, 500
    # ):
    #     return ResumptionClassification.unsafe(
    #         "no titles, but from success to error on resumption"
    #     )
    # if initial.status_code in range(400, 500) and resumption.status_code in range(
    #     200, 300
    # ):
    #     return ResumptionClassification.unsafe(
    #         "no contetitles, but from error to success on resumption"
    #     )

    # if initial.status_code in range(400, 500):
    #     return ResumptionClassification.not_applicable(
    #         "Initial was error, title and body failed us"
    #     )

    # if (
    #     initial.content_length
    #     and resumption.content_length
    #     and initial.content_length != resumption.content_length
    # ):
    #     return ResumptionClassification.unsafe("no titles, but unequal length contents")

    # if initial.status_code != resumption.status_code:
    #     # there really was literally nothing besides status code - did it change?
    #     if initial.body_sha256 is None and resumption.body_sha256 is None:
    #         return ResumptionClassification.not_applicable(
    #             "different status code when completely empty",
    #             initial.status_code,
    #             resumption.status_code,
    #         )

    # else:
    #     # nothing really changed, the content is not really telling, but it was an same length error -> pretty likely an error message
    #     assert initial.status_code == resumption.status_code
    #     if (
    #         initial.status_code in range(400, 500)
    #         and initial.content_length == resumption.content_length
    #     ):
    #         # no real (title) content, but both error, same length is pretty safe
    #         return ResumptionClassification.safe(
    #             "untitled but same format error message"
    #         )

    # TODO decide here...
    return ResumptionClassification.unsafe("unsure")


def get_domains_on_ip(ip):
    _QUERY = """MATCH (x:DOMAIN)--(y:IP {{ip: "{ip}"}}) RETURN DISTINCT x"""
    neo4j_driver = Neo4JDatabase.get_connection()
    query = _QUERY.format(ip=ip)
    records, summary, keys = neo4j_driver.execute_query(query)
    d = [r.data()["x"]["domain"] for r in records]
    logging.debug(f"Got {len(d)} domains on {ip}")
    return d


def get_domain_neighborhood(domain, limit=None):
    _QUERY = """MATCH (x:DOMAIN {{domain:"{base_domain}"}})--(y:PREFIX)--(z:DOMAIN) RETURN DISTINCT z"""
    if limit:
        assert isinstance(limit, int)
        _QUERY += f" LIMIT {limit}"
    neo4j_driver = Neo4JDatabase.get_connection()
    query = _QUERY.format(base_domain=domain, limit=limit)
    records, summary, keys = neo4j_driver.execute_query(query)
    d = [r.data()["z"]["domain"] for r in records]
    logging.debug(f"Got {len(d)} neighbors for {domain}")
    return d


def unique(iterable):
    seen = set()
    for item in iterable:
        if item not in seen:
            seen.add(item)
            yield item


def get_domain_body_and_cert(domain):
    filter = {"domain_from": domain}
    project = {
        "body": "$initial.data.http.result.response.body",
        "cert": "$initial.data.http.result.response.request.tls_log.handshake_log.server_certificates.certificate",
    }

    result = MongoCollection.get_collection().find(filter=filter, projection=project)
    for r in result:
        body, cert = r.get("body"), r.get("cert", {}).get("raw")
        if cert:
            yield body, cert


problematic_domains = {
    # should be fixed with title extraction
    "bm.py",
    # "pm.by",
    # "glotgrx.com",
    # "tradebrains.in",
    # "komonews.com",  # potentially
    # # cannot recreate, perhaps a temporary problem - TITLE_RE works
    # "okcfox.com",
    # # Routing problems
    # "brand-display.com",
    # # weird tlds and redirects to .com
    # "shopee.com.mx",
    # "shopee.com.my",
    # # empty
    # "redfastlabs.com",
    # # should be fixed by title_extration
    # "s-0005.dual-s-msedge.net",
    # "wac-0003.wac-dc-msedge.net.wac-0003.wac-msedge.net",
    # "ns1.a-msedge.net",  # fixed with content length?
    # "meteogiornale.it",  # cannot reproduce - TODO: how to deal with HTTP 202
    # # don't know what to do with you
    # "ipv4.icanhazip.com",  # can only compare content I suppose
    # "dis.criteo.com",  # doesnt even send html
    # "www.affirm.com",
}


def nop():
    pass


def analyze_item_iter(result: Zgrab2ResumptionResult):
    initial: Response = result.initial
    for redirected in result.redirect:
        # redirected: Response = redirected
        try:
            yield classify_resumption(initial, redirected, result.domain_from)
        except Exception as e:
            logging.exception(
                f"Error in classify_resumption ({result.domain_from}, {initial._ip} -> {redirected._ip}): {e}"
            )
            yield ResumptionClassification.not_applicable("exception occured")


def analyze_item(doc):
    del doc["_id"]
    result = Zgrab2ResumptionResult(**doc)
    result.initial = Response(result.initial)
    for i, r in enumerate(result.redirect):
        result.redirect[i] = Response(r)
    return result, list(analyze_item_iter(result))


def limit(iterable, limit):
    for i, item in enumerate(iterable):
        if i >= limit:
            break
        yield item


def analyze_collection(collection):
    results = {type: dict() for type in ResumptionClassificationType}
    db_items = collection.find({"status": "SUCCESS"})
    _COUNT = collection.count_documents({"status": "SUCCESS"})
    _START = time.time()
    _NUM = 0
    _LAST_PRINT = _START
    with ProcessPool() as pool:
        for result, classifications in pool.imap(analyze_item, db_items):
            _NUM += 1
            if _NUM % 1000 == 0 or time.time() - _LAST_PRINT > 60:
                _LAST_PRINT = time.time()
                ETA = datetime.timedelta(seconds=(_COUNT - _NUM) / (_NUM / (time.time() - _START)))
                print(
                    f"Processed {_NUM:}/{_COUNT} ({_NUM/_COUNT:6.2%}) in {time.time()-_START:.2f}s | {_NUM/(time.time()-_START):.2f} items/s | ETA {ETA}",
                )
                sys.stdout.flush()
                pprint(results, stream=sys.stderr)
                sys.stderr.flush()

            found = False
            # if not all(c.is_safe for c in classifications):
            #     print("#" * 80)
            initial = result.initial
            for i, classification in enumerate(classifications):
                redirected = result.redirect[i]

                result_type = results.get(classification.classification)
                if classification.reason in result_type:
                    result_type[classification.reason] += 1
                else:
                    result_type[classification.reason] = 0

                if False and not classification.is_safe:
                    if found:
                        print("-" * 80)
                    found = True
                    print("We got a connection to a different server without authentication")
                    print(
                        f"Ticket from {result.domain_from} at {initial._ip} -> {redirected._ip} in {result.version} | Detected with {classification.reason}"
                    )
                    print("Value Initial   :", repr(classification.value_initial)[:50])
                    print("Value Resumption:", repr(classification.value_redirect)[:50])
                    print("Initial   :", initial)
                    print("Resumption:", redirected)
                    # print(
                    #     f'create_test("scan", Remote("{result.domain_from}", "{initial._ip}"), Remote(None, "{redirected._ip}"), create_reversed=False)'
                    # )
                    #         print(
                    #             f"""
                    # host_ticket = Remote("{result.domain_from}", "{initial._ip}")
                    # host_resumption = Remote("{redirected._ip}")""".strip(
                    #                 "\n"
                    #             )
                    #         )
                    print(f"{result.domain_from}@{initial._ip}|{redirected._ip}")
                    if classification.reason == "unsure":
                        # if result.domain_from not in problematic_domains:
                        #     classify_resumption(initial, redirected, result.domain_from)
                        problematic_domains.add(result.domain_from)
    print("#" * 80)
    pprint(results)


def main():
    mongo_url = f"mongodb://{mongodb_creds.as_str()}@127.0.0.1:27017/?authSource=admin&readPreference=primary&directConnection=true&ssl=true"
    logging.info(f"Connecting to MongoDB")
    mongo_driver = MongoCollection.get_connection(mongo_url, tlsAllowInvalidCertificates=True)
    mongo_driver.server_info()
    logging.info("Main Process connected to MongoDB")

    neo4j_url = f"bolt://localhost:7687"
    logging.info(f"Connecting to Neo4J")
    neo4j_driver = Neo4JDatabase.get_connection(neo4j_url, auth=neo4j_creds.as_tuple())
    neo4j_driver.verify_connectivity()
    logging.info("Main Process connected to Neo4J")

    db = mongo_driver["steckruebe"]
    collection_name = "ticket_redirection_2024-06-12 19:41:10.680922"
    if collection_name:
        collection = MongoCollection.get_collection(database="steckruebe", collection=collection_name)
        analyze_collection(collection)
    else:
        for collection_name in db.list_collection_names():
            collection = MongoCollection.get_collection(database="steckruebe", collection=collection_name)
            logging.info(f"Collection: {collection_name}")
            analyze_collection(collection)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s | %(process)d %(processName)s - %(name)s.%(funcName)s: %(message)s",
    )
    logging.getLogger("neo4j").setLevel(logging.WARNING)
    main()
