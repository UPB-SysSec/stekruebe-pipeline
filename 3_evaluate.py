from collections import Counter
import datetime
import functools
import heapq
import itertools
import logging
import os
import sys
import time
import warnings
from dataclasses import dataclass
from enum import Enum
from multiprocessing.pool import Pool as ProcessPool
from multiprocessing.pool import ThreadPool
from pprint import pformat, pprint
from typing import Optional, Union
from urllib.parse import urlparse

import bson
import Levenshtein
from utils.botp import BagOfTreePaths
import utils.json_serialization as json
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning, XMLParsedAsHTMLWarning
from bson import ObjectId
from neo4j import GraphDatabase
from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator, model_serializer, model_validator
from pymongo import IndexModel
from pymongo.collection import Collection
from pymongo.errors import DocumentTooLarge, _OperationCancelled
from utils.credentials import mongodb_creds, neo4j_creds
from utils.db import MongoCollection, MongoDB, Neo4j, connect_mongo, connect_neo4j, get_most_recent_collection_name
from utils.misc import catch_exceptions
from utils.result import Zgrab2ResumptionResult

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)


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
        self.body_boxp = self._response.get("body_boxp", None)
        self.body_botp = self._response.get("body_botp", None)
        self.location = self._response.get("headers", {}).get("location", [])
        if len(self.location) > 1:
            if len(set(self.location)) == 1:
                logging.info(
                    f"Same location was specified multiple times, reducing to one: {self.location} for {self._ip}"
                )
                self.location = [self.location[0]]
            else:
                logging.warning(f"Multiple distinct locations: {self.location} for {self._ip}")

    def __str__(self) -> str:
        sha_format = f"{self.body_sha256:.6s}" if self.body_sha256 else "None"
        return f"Response(status_code={self.status_code!r}, body_sha256={sha_format}, content_title={self.content_title!r:.50}, content_length={self.content_length!r}, body_len={self.body_len!r}, location={self.location!r})"

    def __repr__(self) -> str:
        return f"Response(status_code={self.status_code!r}, body_sha256={self.body_sha256!r}, content_title={self.content_title!r:.50}, content_length={self.content_length!r}, body_len={self.body_len!r}, location={self.location!r})"


@dataclass
class AnalyzedZgrab2ResumptionResult(Zgrab2ResumptionResult):
    """Convinience Class; transforms initial and redirect into response objects rather than dicts"""

    initial: Response = None
    redirect: list[Response] = None

    def __post_init__(self):
        if self.initial:
            self.initial = Response(self.initial)
        if self.redirect:
            self.redirect = [Response(r) for r in self.redirect]


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
    return levenshtein_ratio(head_a, head_b)


@catch_exceptions
def bag_of_paths_similarity(a, b):
    bag1 = BagOfTreePaths(a)
    bag2 = BagOfTreePaths(b)
    return bag1.similarity(bag2)


# endregion Actual Metrics

# region Metrics Dataclasses and Logic

MetricValue = Optional[float]
MetricName = str
Metrics = dict[MetricName, MetricValue]
BodyId = str


def compute_single_metrics(resumption_body: str, other_body: str, key_prefix=""):
    ret = {}
    if resumption_body and other_body:
        ret.update(
            {
                f"{key_prefix}levenshtein_similarity": levenshtein_ratio(resumption_body, other_body),
                f"{key_prefix}levenshtein_header_similarity": levenshtein_header_similarity(
                    resumption_body, other_body
                ),
                f"{key_prefix}radoy_header_similarity": radoy_header_ratio(resumption_body, other_body),
                f"{key_prefix}bag_of_paths_similarity": bag_of_paths_similarity(resumption_body, other_body),
            }
        )
    return ret


def compute_single_metrics_with_initial(initial_body: str, resumption_body: str, other_body: str):
    ret = {}
    if resumption_body and other_body:
        ret.update(compute_single_metrics(resumption_body, other_body))
        ret.update(compute_single_metrics(initial_body, other_body, key_prefix="initial_"))
    return ret


class _MinMaxHolder(BaseModel):
    min: tuple[str, MetricValue] = Field(default=(None, None))
    max: tuple[str, MetricValue] = Field(default=(None, None))

    def update(self, key, value):
        if self.max[0] is None or value > self.max[1]:
            self.max = (key, value)
        if self.min[0] is None or value < self.min[1]:
            self.min = (key, value)


@dataclass
class ComputedMetricsSummary(BaseModel):
    initial_value: float
    same_cert: _MinMaxHolder = Field(default_factory=_MinMaxHolder)
    diff_cert: _MinMaxHolder = Field(default_factory=_MinMaxHolder)

    @model_serializer()
    def _serialize(self):
        # flatten the structure
        return {
            "initial_value": self.initial_value,
            "max_same_cert_name": self.same_cert.max[0],
            "max_same_cert_value": self.same_cert.max[1],
            "max_diff_cert_name": self.diff_cert.max[0],
            "max_diff_cert_value": self.diff_cert.max[1],
            "min_same_cert_name": self.same_cert.min[0],
            "min_same_cert_value": self.same_cert.min[1],
            "min_diff_cert_name": self.diff_cert.min[0],
            "min_diff_cert_value": self.diff_cert.min[1],
        }

    @model_validator(mode="before")
    @classmethod
    def _load(cls, v):
        return {
            "initial_value": v["initial_value"],
            "same_cert": {
                "min": (v["min_same_cert_name"], v["min_same_cert_value"]),
                "max": (v["max_same_cert_name"], v["max_same_cert_value"]),
            },
            "diff_cert": {
                "min": (v["min_diff_cert_name"], v["min_diff_cert_value"]),
                "max": (v["max_diff_cert_name"], v["max_diff_cert_value"]),
            },
        }

    def update(self, same_cert, key: str, value: float):
        if same_cert:
            self.same_cert.update(key, value)
        else:
            self.diff_cert.update(key, value)

    def to_dict(self):
        # dirty way to convert to serializable for DB
        return json.loads(json.dumps(self))


x = _MinMaxHolder()
x = ComputedMetricsSummary(initial_value=1)

Heap = list
METRIC_KEEP = 10


class _MetricsHolder(BaseModel):

    details: dict[BodyId, Metrics] = Field(default_factory=dict)
    metrics_sorted: dict[MetricName, Heap[tuple[MetricValue, BodyId]]] = Field(default_factory=dict, exclude=True)

    @model_serializer()
    def serialize(self):
        return self.details

    @model_validator(mode="wrap")
    @classmethod
    def _load(cls, v, handler, info):
        self: _MetricsHolder = handler(v)
        len_before = len(v)
        for key, metrics in v.items():
            self.add_metric(key, metrics)
        assert len(self.details) == len_before
        return self

    def add_metric(self, key, metrics):
        details_drop = set()
        should_add_to_details = False

        for metric_name, value in metrics.items():
            if metric_name not in self.metrics_sorted:
                self.metrics_sorted[metric_name] = Heap()

            sorted_list = self.metrics_sorted[metric_name]
            if len(sorted_list) < METRIC_KEEP:
                should_add_to_details = True
                heapq.heappush(sorted_list, (value, key))
            else:
                # heap keeps the smallest value at first place
                smallest_value, smallest_name = sorted_list[0]
                if value > smallest_value:
                    should_add_to_details = True
                    details_drop.add(smallest_name)
                    _val, _name = heapq.heappushpop(sorted_list, (value, key))
                    assert _val == smallest_value
                    assert _name == smallest_name

        if should_add_to_details:
            self.details[key] = metrics
        for key in details_drop:
            skip_remove = False
            for lst in self.metrics_sorted.values():
                for _, bid in lst:
                    if bid == key:
                        skip_remove = True
                        break
                if skip_remove:
                    break
            if not skip_remove:
                # no other set contains this key
                del self.details[key]


def _test_metrics_holder():
    # SELF TEST
    global METRIC_KEEP
    METRIC_KEEP = 2
    holder = _MetricsHolder()
    holder.add_metric("a", {"m1": 1, "m2": 1, "m3": 1})
    holder.add_metric("b", {"m1": 9, "m2": 1, "m3": 1})
    assert holder.model_dump().keys() == {"a", "b"}
    holder.add_metric("c", {"m1": 0, "m2": 0, "m3": 0})
    holder.add_metric("d", {"m1": 2, "m2": 2, "m3": 2})
    assert holder.model_dump().keys() == {"b", "d"}
    holder.add_metric("e", {"m1": 1, "m2": 9, "m3": 1})
    assert holder.model_dump().keys() == {"b", "d", "e"}
    holder.add_metric("f", {"m1": 10, "m2": 8, "m3": 1})
    assert holder.model_dump().keys() == {"b", "d", "e", "f"}
    holder.add_metric("g", {"m1": 42, "m2": 42, "m3": 42})
    assert holder.model_dump().keys() == {"d", "e", "f", "g"}
    holder.add_metric("h", {"m1": 42, "m2": 42, "m3": 42})
    assert holder.model_dump().keys() == {"g", "h"}


_test_metrics_holder()
del _test_metrics_holder


class ComputedMetricsHolder(BaseModel):
    metrics_summary: dict[MetricName, ComputedMetricsSummary] = Field(default_factory=dict)
    initial_details: Optional[Metrics]
    same_cert_details: _MetricsHolder = Field(default_factory=_MetricsHolder)
    diff_cert_details: _MetricsHolder = Field(default_factory=_MetricsHolder)

    def add_metrics(self, same_cert, key: BodyId, metrics: Metrics):
        if key == "initial":
            for mname, mvalue in metrics.items():
                self.metrics_summary[mname] = ComputedMetricsSummary(mvalue)
            return

        if same_cert:
            self.same_cert_details.add_metric(key, metrics)
        else:
            self.diff_cert_details.add_metric(key, metrics)

        # update summary
        for mname, mvalue in metrics.items():
            if mname not in self.metrics_summary:
                initial_value = self.initial_details.get(mname, None) if self.initial_details else None
                self.metrics_summary[mname] = ComputedMetricsSummary(initial_value=initial_value)
            self.metrics_summary[mname].update(same_cert, key, mvalue)

    def to_dict(self):
        return self.model_dump()


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
    if len(ids) > 1000:
        if isinstance(ids, set):
            ids = list(ids)
        # Too many ids, will fetch in chunks
        for i in range(0, len(ids), 1000):
            yield from get_body_cert_for_ids(ids[i : i + 1000])
        return

    filter = {"_id": {"$in": [ObjectId(bytes.fromhex(id)) for id in ids]}}
    project = {
        "body": "$initial.data.http.result.response.body",
        "cert": "$initial.data.http.result.response.request.tls_log.handshake_log.server_certificates.certificate",
    }

    try:
        results = ScanContext.mongo_collection.find(filter=filter, projection=project)
        results = list(results)  # fetch immediately
    except _OperationCancelled:
        logging.critical("Operation cancelled: %d ids=%s", len(ids), ids)
        raise
    for r in results:
        id = r.get("_id")
        body = r.get("body")
        cert = r.get("cert", {}).get("raw")
        if cert:
            yield id.binary.hex(), (body, cert)


def compute_metrics(initial: Response, resumption: Response, domain_from: str, initial_doc_id):
    if not resumption.body:
        return None
    if not resumption.resumed:
        return None

    ret = ComputedMetricsHolder(initial_details=compute_single_metrics(resumption.body, initial.body))

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
            ret.add_metrics(
                initial.certificate == neighbor_cert,
                key,
                compute_single_metrics_with_initial(initial.body, resumption.body, neighbor_body),
            )

    return ret


# endregion Metrics Dataclasses and Logic

# region Classification

class ResumptionClassificationType(Enum):
    NOT_APPLICABLE = 0
    SAFE = 1
    UNSAFE = 2
    LOOK_AT_METRICS = 3

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
    def look_at_metrics():
        return ResumptionClassification(ResumptionClassificationType.LOOK_AT_METRICS, "need to classify using metrics")

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
            if len(initial.location) > 1 or len(resumption.location) > 1:
                return ResumptionClassification.not_applicable(
                    "multiple locations specified in one response", initial.location, resumption.location
                )
            # or at least same origin?
            return ResumptionClassification.assert_true(
                are_same_origin(initial.location[0], resumption.location[0]),
                initial.location[0],
                resumption.location[0],
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
        if not resumption.location:
            return ResumptionClassification.not_applicable("resumption had no location even though 3XX code set")
        if len(resumption.location) > 1:
            return ResumptionClassification.not_applicable(
                "multiple locations specified in one response (initial was no redirect)", resumption.location
            )
        parsed_location = urlparse(resumption.location[0].lower())
        if not parsed_location.hostname and not parsed_location.scheme:
            # relative path -> NA
            return ResumptionClassification.not_applicable("relative redirect on resumption", b=resumption.location[0])

        if parsed_location.netloc == domain_from:
            if parsed_location.scheme == "https":
                return ResumptionClassification.safe("redirect to original (https)", b=resumption.location[0])
            if parsed_location.scheme == "http":
                return ResumptionClassification.safe("redirect to original (http)", b=resumption.location[0])
            if not parsed_location.scheme:
                return ResumptionClassification.safe(
                    "redirect to original (no scheme/implicit https)", b=resumption.location[0]
                )
            return ResumptionClassification.not_applicable(
                "redirect to original (other scheme)", b=resumption.location[0]
            )
        if parsed_location.netloc == "www." + domain_from:
            if parsed_location.scheme == "https":
                return ResumptionClassification.safe("redirect to www.original (https)", b=resumption.location[0])
            if parsed_location.scheme == "http":
                return ResumptionClassification.safe("redirect to www.original (http)", b=resumption.location[0])
            if not parsed_location.scheme:
                return ResumptionClassification.safe(
                    "redirect to www.original (no scheme/implicit https)", b=resumption.location[0]
                )
            return ResumptionClassification.not_applicable(
                "redirect to www.original (other scheme)", b=resumption.location[0]
            )

        return ResumptionClassification.unsafe("redirect to different", None, resumption.location[0])

    if initial.body_sha256 is not None and initial.body_sha256 == resumption.body_sha256:
        # same content
        return ResumptionClassification.safe("body sha256")
    return ResumptionClassification.look_at_metrics()


# endregion Classification


def analyze_item_iter(result: AnalyzedZgrab2ResumptionResult, initial_doc_id):
    for redirected in result.redirect:
        # redirected: Response = redirected
        try:
            yield (
                classify_resumption(result.initial, redirected, result.domain_from),
                compute_metrics(result.initial, redirected, result.domain_from, initial_doc_id),
            )
        except Exception as e:
            logging.exception(
                f"Error in classify_resumption ({result.domain_from}, {result.initial._ip} -> {redirected._ip}): {e}"
            )
            raise
            yield ResumptionClassification.not_applicable("exception occured"), None


def bson_length(doc):
    if isinstance(doc, dict):
        return len(bson.BSON.encode(doc))
    return -1


def analyze_item(doc, insert_result: bool = True):
    doc_id: ObjectId = doc["_id"]
    _doc_size = bson_length(doc)
    del doc["_id"]
    if "_analyzed" in doc:
        del doc["_analyzed"]

    result = AnalyzedZgrab2ResumptionResult(**doc)
    resumption_classifications_and_metrics = list(analyze_item_iter(result, doc_id))

    # also compute similarities for initial connection, may be useful to ultimately classify resumptions
    # thus far only the similarities of the resumption and other domains (X) has been computed
    # we now compare the initial connection to all X and store the results
    update_set = {"_analyzed": True}
    initial_metrics = None
    if resumption_classifications_and_metrics:
        # initial_metrics = compute_initial_metrics(result, resumption_classifications_and_metrics)

        # if initial_metrics is not None:
        #     {"initial._metrics": initial_metrics.to_dict()}
        for i, (classification, metrics) in enumerate(resumption_classifications_and_metrics):
            update_set[f"redirect.{i}._classification"] = classification.to_dict()
            if metrics is not None:
                update_set[f"redirect.{i}._metrics"] = metrics.to_dict()

    if insert_result:
        try:
            ScanContext.mongo_collection.update_one({"_id": doc_id}, {"$set": update_set}, upsert=False)
        except DocumentTooLarge as e:
            _update_size = bson_length(update_set)
            logging.critical(f"Error updating {doc_id}: {e}")
            for k, v in update_set.items():
                logging.critical(f"- update.{k}: {bson_length(v):,}")
            if resumption_classifications_and_metrics:
                logging.critical(f"Compared initial body with {len(initial_metrics.domain_details):,} other bodies")
                for i, (_, metrics) in enumerate(resumption_classifications_and_metrics):
                    if metrics is not None:
                        logging.critical(f"Compared redirect.{i} with {len(metrics.domain_details):,} other bodies")
                    else:
                        logging.critical(f"Compared redirect.{i} with no other bodies")
            else:
                logging.critical(f"Update set: {update_set}")
            logging.critical(f"Initial document size: {_doc_size:,}, update size: {_update_size:,}")
            logging.error("Error updating %s; skipping and setting it to alledgedly analyzed :eyes:", doc_id)
            update_set = {"_analyzed": True, "_analysis_errored": True}
            ScanContext.mongo_collection.update_one({"_id": doc_id}, {"$set": update_set}, upsert=False)
    else:
        logging.info(f"Would update {doc_id} ({result.domain_from}) with \n{pformat(update_set)}")

    return result, resumption_classifications_and_metrics


def analyze_collection(collection_filter=...):
    if collection_filter is ...:
        collection_filter = {"status": "SUCCESS", "_analyzed": {"$ne": True}}
    logging.info("Creating index for analyzed flag")
    ScanContext.mongo_collection.create_indexes(
        [
            IndexModel("_analyzed"),
            IndexModel([("status", 1), ("_analyzed", 1)]),
        ]
    )

    # index creation blocks, hence removed for now
    # the index is only useful in hindsight, so we actually do not care too much now
    # logging.info("Creating index for eval results")
    # ScanContext.mongo_collection.create_index("initial._metrics", sparse=True)
    results = {typ: dict() for typ in ResumptionClassificationType}
    db_items = ScanContext.mongo_collection.find(collection_filter)
    logging.info("Counting documents")
    _COUNT = ScanContext.mongo_collection.count_documents(collection_filter)
    _START = time.time()
    _NUM = 0
    _LAST_PRINT = _START
    _LAST_STAT_PRINT = _START

    # cleanup_db()
    # return
    logging.info("Starting (total=%d)", _COUNT)
    with ProcessPool() as pool:
        for result, classifications_and_metrics in pool.imap_unordered(analyze_item, db_items):
            _NUM += 1
            if time.time() - _LAST_PRINT > 60:
                _LAST_PRINT = time.time()
                ETA = datetime.timedelta(seconds=(_COUNT - _NUM) / (_NUM / (time.time() - _START)))
                if time.time() - _LAST_STAT_PRINT > 600:
                    _LAST_STAT_PRINT = _LAST_PRINT
                    pprint(results)
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


def test(mongo_collection_name=None):
    from tqdm import tqdm

    ScanContext.initialize(mongo_collection_name=mongo_collection_name)
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
        format="%(asctime)s %(levelname)-8s | %(process)d %(processName)s - %(name)s.%(funcName)s: %(message)s",
    )
    logging.getLogger("neo4j").setLevel(logging.CRITICAL)
    # main()
    test("test")
