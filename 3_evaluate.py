import itertools
import logging
from pprint import pprint, pformat
from neo4j import GraphDatabase
from bson import ObjectId
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
import utils.json_serialization as json
from utils.db import MongoDB, MongoCollection, Neo4j, connect_mongo, connect_neo4j, get_most_recent_collection_name
from pymongo.collection import Collection
from urllib.parse import urlparse
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
import warnings

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)


class ScanContext:
    neo4j: GraphDatabase = None
    mongo_collection: Collection = None

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


# @functools.lru_cache(maxsize=1024 * 1024 * 10)
@functools.wraps(Levenshtein.ratio)
def levenshtein_ratio(a, b):
    return Levenshtein.ratio(a, b)


# TODO modify constants to obtain better results
def compare_entry(entry1, entry2):
    if entry1.name == "script" and entry2.name == "script":
        if entry1.has_attr("nonce"): entry1["nonce"] = "rand"
        if entry2.has_attr("nonce"): entry2["nonce"] = "rand"
        if entry1.has_attr("src") and entry2.has_attr("src"):
            src1 = entry1["src"].split("?")[0]
            src2 = entry2["src"].split("?")[0]
            return src1 == src2
        if Levenshtein.ratio(str(entry1), str(entry2)) > 0.75: return True
    if entry1.name == "title" and entry2.name == "title":
        # We can't match titles, but we hope that both have a title tag
        return True
    if entry1.name == "meta" and entry2.name == "meta":
        if entry1.has_attr("content") and entry2.has_attr("content"):
            return True
    if entry1.name == "meta" and entry2.name == "meta":
        if (entry1.has_attr("og_title") and entry2.has_attr("og_title")
                and entry1.has_attr("content") and entry2.has_attr("content")):
            # We can't match titles, but if both meta tags are there we say they match somewhat
            return True
    # TODO Add other cases if found

    return False


def radoy_header_ratio(a, b):
    soup1 = BeautifulSoup(a, 'html.parser')
    soup2 = BeautifulSoup(b, 'html.parser')
    head1 = soup1.head
    head2 = soup2.head
    if head1 is None and head2 is not None or head1 is not None and head2 is None:
        return 0
    if head1 is None and head2 is None:
        # This is kind of a similar, but we set -1 since our test  is not applicable
        return -1

    penalty = 0
    penalty += 0.5*(abs(len(list(head1.children)) - len(list(head2.children)))**1.4)

    if len(head1.children)<len(head2.children): head1,head2=head2,head1
    for (x, y) in itertools.zip_longest(head1.children, head2.children):
        if x != y and not compare_entry(x, y):
            # Penalty for mismatch (deducted when found in the next step)
            penalty += 1.1
            for r in head2.find_all(x.name):
                if compare_entry(x, r):
                    # We found a similar enough entry so let's deduct the penalty partly (position was still wrong)
                    penalty -= 0.9
                    break

    return max(0, min(1, 1 - (penalty / len(list(soup1.head.children)))))


def extract_head(html: str, tag="head"):
    # naive way to find head
    start = html.find(f"<head")
    end = html.find("</head")
    if start == -1 and end == -1:
        # no head in here
        return ""
    if end == -1:
        # end was probably cut off
        return html[start:]
    return html[start:end]


def levenshtein_header_similarity(a, b):
    head_a = extract_head(a)
    head_b = extract_head(b)
    return levenshtein_ratio(head_a, head_b)


@dataclass
class ComputedMetrics:
    same_cert: bool
    levenshtein_similarity: float
    levenshtein_header_similarity: float
    radoy_header_similarity: float

    @staticmethod
    def from_response(same_cert, body_resumption, body_other):
        return ComputedMetrics(
            same_cert=same_cert,
            levenshtein_similarity=levenshtein_ratio(body_resumption, body_other),
            levenshtein_header_similarity=levenshtein_header_similarity(body_resumption, body_other),
            radoy_header_similarity=radoy_header_ratio(body_resumption, body_other),
        )

    def to_dict(self):
        # dirty way to convert to serializable for DB
        return json.loads(json.dumps(self))


@dataclass
class ComputedMetricsSummary:
    initial_value: float
    min_same_cert_name: str
    min_same_cert_value: float
    min_diff_cert_name: str
    min_diff_cert_value: float
    max_same_cert_name: str
    max_same_cert_value: float
    max_diff_cert_name: str
    max_diff_cert_value: float

    def to_dict(self):
        # dirty way to convert to serializable for DB
        return json.loads(json.dumps(self))


@dataclass
class ComputedMetricsHolder:
    metrics_summary: dict[str, ComputedMetricsSummary]
    domain_details: dict[str, ComputedMetrics]

    def to_dict(self):
        # dirty way to convert to serializable for DB
        return json.loads(json.dumps(self))


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
    def safe(reason, a=None, b=None):
        return ResumptionClassification(ResumptionClassificationType.SAFE, reason, a, b)

    @staticmethod
    def not_applicable(reason, a=None, b=None):
        return ResumptionClassification(ResumptionClassificationType.NOT_APPLICABLE, reason, a, b)

    @staticmethod
    def unsafe(reason, a=None, b=None):
        return ResumptionClassification(ResumptionClassificationType.UNSAFE, reason, a, b)

    @staticmethod
    def assert_equal(a, b, reason):
        return ResumptionClassification(a == b, reason, a, b)

    @staticmethod
    def assert_true(truthy, a, b, reason):
        return ResumptionClassification(bool(truthy), reason, a, b)

    def to_dict(self):
        # dirty way to convert to serializable for DB
        return json.loads(json.dumps(self))


@dataclass
class AnalyzedZgrab2ResumptionResult(Zgrab2ResumptionResult):
    initial: Response = None
    redirect: list[Response] = None

    def __post_init__(self):
        if self.initial:
            self.initial = Response(self.initial)
        if self.redirect:
            self.redirect = [Response(r) for r in self.redirect]


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


def are_same_origin(url1, url2):
    p1 = urlparse(url1)
    p2 = urlparse(url2)
    return p1.scheme == p2.scheme and p1.port == p2.port and p1.hostname == p2.hostname


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
        if not initial.location:
            return ResumptionClassification.not_applicable("initial redirection had no location set")
        if resumption.status_code in range(300, 400):
            if not resumption.location:
                return ResumptionClassification.not_applicable("resumption redirection had no location set")
            # ... on resumption as well - was the location the same?
            if initial.location == resumption.location:
                return ResumptionClassification.safe("location", initial.location, resumption.location)
            # or at least same origin?
            return ResumptionClassification.assert_true(
                are_same_origin(initial.location, resumption.location),
                initial.location,
                resumption.location,
                "location SOP",
            )
        # ... but not on resumption - which means the server is handling us differently
        return ResumptionClassification.unsafe(
            "initial was redirect, resumption was not",
            initial.status_code,
            resumption.status_code,
        )

    # if resumption 300 and initial 200 check redirect to original
    if resumption.status_code in range(300, 400):
        assert resumption.location
        parsed_location = urlparse(resumption.location.lower())
        if not parsed_location.hostname and not parsed_location.scheme:
            # relative path -> NA
            return ResumptionClassification.not_applicable("relative redirect on resumption", b=resumption.location)

        if parsed_location.netloc == domain_from:
            if parsed_location.scheme == "https":
                return ResumptionClassification.safe("redirect to original (https)", b=resumption.location)
            if parsed_location.scheme == "http":
                return ResumptionClassification.safe("redirect to original (http)", b=resumption.location)
            if not parsed_location.scheme:
                return ResumptionClassification.safe(
                    "redirect to original (no scheme/implicit https)", b=resumption.location
                )
            return ResumptionClassification.not_applicable("redirect to original (other scheme)", b=resumption.location)
        if parsed_location.netloc == "www." + domain_from:
            if parsed_location.scheme == "https":
                return ResumptionClassification.safe("redirect to www.original (https)", b=resumption.location)
            if parsed_location.scheme == "http":
                return ResumptionClassification.safe("redirect to www.original (http)", b=resumption.location)
            if not parsed_location.scheme:
                return ResumptionClassification.safe(
                    "redirect to www.original (no scheme/implicit https)", b=resumption.location
                )
            return ResumptionClassification.not_applicable(
                "redirect to www.original (other scheme)", b=resumption.location
            )

        return ResumptionClassification.unsafe("redirect to different", None, resumption.location)

    if initial.body_sha256 is not None and initial.body_sha256 == resumption.body_sha256:
        # same content
        return ResumptionClassification.safe("body sha256")
    return ResumptionClassification.not_applicable("No easy way out -> metrics")


def summarize_metrics(domain_ratios: dict[str, ComputedMetrics]) -> dict[str, ComputedMetricsSummary]:
    # compute summary; for each metric find min/max for same/diff cert
    summary = {}
    ratio_names = [x[0] for x in ComputedMetrics.__dataclass_fields__.items() if x[1].type == float]
    for ratio_name in ratio_names:
        initial_value = None
        if "initial" in domain_ratios:
            initial_value = getattr(domain_ratios["initial"], ratio_name)
        # ugly code, but it works :shrug:
        min_same_cert_name = None
        min_same_cert_value = None
        min_diff_cert_name = None
        min_diff_cert_value = None
        max_same_cert_name = None
        max_same_cert_value = None
        max_diff_cert_name = None
        max_diff_cert_value = None
        for k, v in domain_ratios.items():
            if k == "initial":
                continue
            ratio = getattr(v, ratio_name)
            if v.same_cert:
                if not min_same_cert_name or ratio < min_same_cert_value:
                    min_same_cert_name = k
                    min_same_cert_value = ratio
                if not max_same_cert_name or ratio > max_same_cert_value:
                    max_same_cert_name = k
                    max_same_cert_value = ratio
            else:
                if not min_diff_cert_name or ratio < min_diff_cert_value:
                    min_diff_cert_name = k
                    min_diff_cert_value = ratio
                if not max_diff_cert_name or ratio > max_diff_cert_value:
                    max_diff_cert_name = k
                    max_diff_cert_value = ratio
        summary[ratio_name] = ComputedMetricsSummary(
            initial_value=initial_value,
            min_same_cert_name=min_same_cert_name,
            min_same_cert_value=min_same_cert_value,
            min_diff_cert_name=min_diff_cert_name,
            min_diff_cert_value=min_diff_cert_value,
            max_same_cert_name=max_same_cert_name,
            max_same_cert_value=max_same_cert_value,
            max_diff_cert_name=max_diff_cert_name,
            max_diff_cert_value=max_diff_cert_value,
        )
    return summary


def compute_metrics(initial: Response, resumption: Response, domain_from: str, initial_doc_id):
    if not resumption.body:
        return None
    if not resumption.resumed:
        return None

    domain_ratios = {"initial": ComputedMetrics.from_response(True, resumption.body, initial.body)}
    relevant_domains = set(
        get_domains_on_ip(resumption._ip)
        + extract_subjects(initial.parsed_certificate)
        # + get_domain_neighborhood(domain_from)
    )
    for neighbor_domain in relevant_domains:
        for neighbor_body, neighbor_cert, neighbor_id in get_body_cert_id_for_domain(neighbor_domain):
            if neighbor_id == initial_doc_id:
                # we already computed 'initial' separately
                continue
            if not neighbor_body:
                continue
            key = f"{neighbor_domain}[{neighbor_id}]"
            assert key not in domain_ratios
            domain_ratios[key] = ComputedMetrics.from_response(
                initial.certificate == neighbor_cert, resumption.body, neighbor_body
            )

    return ComputedMetricsHolder(metrics_summary=summarize_metrics(domain_ratios), domain_details=domain_ratios)


def get_domains_on_ip(ip):
    _QUERY = """MATCH (x:DOMAIN)--(y:IP {{ip: "{ip}"}}) RETURN DISTINCT x"""
    query = _QUERY.format(ip=ip)
    records, summary, keys = ScanContext.neo4j.execute_query(query)
    d = [r.data()["x"]["domain"] for r in records]
    logging.debug(f"Got {len(d)} domains on {ip}")
    return d


def get_domain_neighborhood(domain, limit=None):
    _QUERY = """MATCH (x:DOMAIN {{domain:"{base_domain}"}})--(y:PREFIX)--(z:DOMAIN) RETURN DISTINCT z"""
    if limit:
        assert isinstance(limit, int)
        _QUERY += f" LIMIT {limit}"
    query = _QUERY.format(base_domain=domain, limit=limit)
    records, summary, keys = ScanContext.neo4j.execute_query(query)
    d = [r.data()["z"]["domain"] for r in records]
    logging.debug(f"Got {len(d)} neighbors for {domain}")
    return d


def get_body_cert_id_for_domain(domain):
    filter = {"domain_from": domain}
    project = {
        "body": "$initial.data.http.result.response.body",
        "cert": "$initial.data.http.result.response.request.tls_log.handshake_log.server_certificates.certificate",
    }

    result = ScanContext.mongo_collection.find(filter=filter, projection=project)
    seen_body_certs = set()
    for r in result:
        body = r.get("body")
        cert = r.get("cert", {}).get("raw")
        id = r.get("_id")
        if cert:
            ret = (body, cert)
            if ret not in seen_body_certs:
                seen_body_certs.add(ret)
                yield body, cert, id


def get_body_cert_for_ids(ids: list):
    filter = {"_id": {"$in": [ObjectId(bytes.fromhex(id)) for id in ids]}}
    project = {
        "body": "$initial.data.http.result.response.body",
        "cert": "$initial.data.http.result.response.request.tls_log.handshake_log.server_certificates.certificate",
    }

    result = ScanContext.mongo_collection.find(filter=filter, projection=project)
    for r in result:
        id = r.get("_id")
        body = r.get("body")
        cert = r.get("cert", {}).get("raw")
        if cert:
            yield id.binary.hex(), (body, cert)


def analyze_item_iter(result: AnalyzedZgrab2ResumptionResult, initial_doc_id):
    for redirected in result.redirect:
        # redirected: Response = redirected
        try:
            yield classify_resumption(result.initial, redirected, result.domain_from), compute_metrics(
                result.initial, redirected, result.domain_from, initial_doc_id
            )
        except Exception as e:
            logging.exception(
                f"Error in classify_resumption ({result.domain_from}, {result.initial._ip} -> {redirected._ip}): {e}"
            )
            yield ResumptionClassification.not_applicable("exception occured"), None


def compute_initial_metrics(result: AnalyzedZgrab2ResumptionResult, resumption_classifications_and_metrics):
    id_to_domain = {}
    ids = set()
    for classification, metrcis_holder in resumption_classifications_and_metrics:
        if metrcis_holder is not None:
            for key in metrcis_holder.domain_details:
                if "[" in key:
                    domain, body_id = key.split("[", 1)
                    body_id = body_id.rstrip("]")
                    ids.add(body_id)
                    id_to_domain[body_id] = domain

    body_certs = dict(get_body_cert_for_ids(ids))

    initial_metrics = {}
    for id in ids:
        domain = id_to_domain[id]
        body, cert = body_certs[id]
        key = f"{domain}[{id}]"
        initial_metrics[key] = ComputedMetrics.from_response(
            result.initial.certificate == cert, result.initial.body, body
        )
    if not initial_metrics:
        return None
    return ComputedMetricsHolder(metrics_summary=summarize_metrics(initial_metrics), domain_details=initial_metrics)


def analyze_item(doc, insert_result: bool = True):
    doc_id: ObjectId = doc["_id"]
    del doc["_id"]
    result = AnalyzedZgrab2ResumptionResult(**doc)
    resumption_classifications_and_metrics = list(analyze_item_iter(result, doc_id))

    # also compute similarities for initial connection, may be useful to ultimately classify resumptions
    # thus far only the similarities of the resumption and other domains (X) has been computed
    # we now compare the initial connection to all X and store the results
    if resumption_classifications_and_metrics:
        initial_metrics = compute_initial_metrics(result, resumption_classifications_and_metrics)

        update_set = {}
        if initial_metrics is not None:
            {"initial._metrics": initial_metrics.to_dict()}
        for i, (classification, metrics) in enumerate(resumption_classifications_and_metrics):
            update_set[f"redirect.{i}._classification"] = classification.to_dict()
            if metrics is not None:
                update_set[f"redirect.{i}._metrics"] = metrics.to_dict()
        if insert_result:
            ScanContext.mongo_collection.update_one({"_id": doc_id}, {"$set": update_set}, upsert=False)
        else:
            logging.info(f"Would update {doc_id} ({result.domain_from}) with \n{pformat(update_set)}")

    return result, resumption_classifications_and_metrics


def limit(iterable, limit):
    for i, item in enumerate(iterable):
        if i >= limit:
            break
        yield item


def cleanup_db():
    logging.info("Cleaning up DB")
    docs_cleant_up = 0
    fields_removed = 0
    for doc in ScanContext.mongo_collection.find({"initial._similarities": {"$exists": True}}):
        fields_to_remove = {"initial._similarities"}
        for i, redirect in enumerate(doc["redirect"]):
            if "_classification" in redirect:
                fields_to_remove.add(f"redirect.{i}._classification")
        update = {"$unset": {x: 1 for x in fields_to_remove}}
        fields_removed += len(fields_to_remove)
        docs_cleant_up += 1
        logging.debug(f"Cleaning up {doc['_id']}: removing {fields_to_remove}")
        ScanContext.mongo_collection.update_one({"_id": doc["_id"]}, update, upsert=False)
    logging.info(f"Cleaned up {docs_cleant_up} documents, removed {fields_removed} fields")


def analyze_collection(collection_filter=...):
    if collection_filter is ...:
        collection_filter = {"status": "SUCCESS"}
    ScanContext.mongo_collection.create_index("initial._metrics", sparse=True)
    results = {typ: dict() for typ in ResumptionClassificationType}
    db_items = ScanContext.mongo_collection.find(collection_filter)
    _COUNT = ScanContext.mongo_collection.count_documents(collection_filter)
    _START = time.time()
    _NUM = 0
    _LAST_PRINT = _START

    # cleanup_db()
    # return
    logging.info("Starting")
    with ProcessPool() as pool:
        # with ThreadPool(1) as pool:
        for result, classifications_and_metrics in pool.imap_unordered(analyze_item, db_items):
            _NUM += 1
            if _NUM % 1000 == 0 or time.time() - _LAST_PRINT > 60:
                _LAST_PRINT = time.time()
                ETA = datetime.timedelta(seconds=(_COUNT - _NUM) / (_NUM / (time.time() - _START)))
                pprint(results, stream=sys.stderr)
                sys.stderr.flush()
                print(
                    f"Processed {_NUM:}/{_COUNT} ({_NUM / _COUNT:6.2%}) in {time.time() - _START:.2f}s | {_NUM / (time.time() - _START):.2f} items/s | ETA {ETA}",
                )
                sys.stdout.flush()

            for i, (classification, metrics) in enumerate(classifications_and_metrics):
                result_type = results.get(classification.classification)
                reason = classification.reason
                if reason not in result_type:
                    result_type[reason] = 0
                result_type[reason] += 1
    print("#" * 80)
    pprint(results)


def main(collection_name=None, collection_filter=...):
    ScanContext.initialize(collection_name, verify_connectivity=True)
    analyze_collection(collection_filter=collection_filter)


def test():
    from tqdm import tqdm

    ScanContext.initialize()
    collection_filter = {"redirect.data.http.result.response.status_code": 200}
    query_limit = 1000
    db_items = ScanContext.mongo_collection.find(collection_filter, limit=query_limit)
    _COUNT = ScanContext.mongo_collection.count_documents(collection_filter, limit=query_limit)

    results = {typ: dict() for typ in ResumptionClassificationType}
    for item in tqdm(db_items, total=_COUNT):
        item_name = f"{item['_id']}, {item['domain_from']}"
        _, classifications_and_metrics = analyze_item(item, insert_result=False)
        if not classifications_and_metrics:
            print(f"No classifications {item_name}")
        for classification, metrics in classifications_and_metrics:
            result_type = results.get(classification.classification)
            reason = classification.reason
            if reason not in result_type:
                result_type[reason] = 0
            result_type[reason] += 1
    print("DONE")
    pprint(results)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s | %(process)d %(processName)s - %(name)s.%(funcName)s: %(message)s",
    )
    logging.getLogger("neo4j").setLevel(logging.WARNING)
    # main()
    test()
