# get html from two urls and compare them using utils.botp

import functools
import itertools
import time
import Levenshtein
import requests
from bs4 import BeautifulSoup
import tqdm
from utils.botp import BagOfTreePaths, BagOfXPaths

# @functools.lru_cache(maxsize=1024 * 1024 * 10)
@functools.wraps(Levenshtein.ratio)
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

def levenshtein_header_similarity(a, b):
    head_a = extract_head(a)
    head_b = extract_head(b)
    return levenshtein_ratio(head_a, head_b)


def binary_bag_of_tree_paths_similarity(a, b):
    botp1 = BagOfTreePaths(a)
    botp2 = BagOfTreePaths(b)
    return botp1.similarity(botp2)

def bag_of_tree_paths_similarity(a, b):
    botp1 = BagOfTreePaths(a)
    botp2 = BagOfTreePaths(b)
    return botp1.similarity(botp2, True)

def binary_bag_of_xpaths_similarity(a, b):
    botp1 = BagOfXPaths(a)
    botp2 = BagOfXPaths(b)
    return botp1.similarity(botp2)

def bag_of_xpaths_similarity(a, b):
    botp1 = BagOfXPaths(a)
    botp2 = BagOfXPaths(b)
    return botp1.similarity(botp2, True)


cache = {}
def get_html(url, cache, LIMIT=1000):
    if url in cache:
        return cache[url]
    if LIMIT is not None:
        html = requests.get(url, timeout=1).text[:LIMIT]
    else:
        html = requests.get(url, timeout=1).text
    cache[url] = html
    return html
# if LIMIT is None, we will get the whole page
# else we will get the first LIMIT bytes
LIMIT = 10_000
for metric in tqdm.tqdm([binary_bag_of_tree_paths_similarity, bag_of_tree_paths_similarity, binary_bag_of_xpaths_similarity, bag_of_xpaths_similarity, levenshtein_ratio, radoy_header_ratio, levenshtein_header_similarity]):
    with open('metrics_test.txt', 'r') as f:
        total_time = 0
        successes = 0
        for line in tqdm.tqdm(f):
            # csv
            url1, url2 = line.strip().split(',')
            # prefix with https
            if not url1.startswith('http'):
                url1 = 'https://' + url1
            if not url2.startswith('http'):
                url2 = 'https://' + url2
            try:
                html1 = get_html(url1, cache, LIMIT)
                html2 = get_html(url2, cache, LIMIT)
            except Exception as e:
                # print("Error:", e)
                continue
            # time metric calculation
            start = time.time()
            res = metric(html1, html2)
            end = time.time()
            # print(f'{metric.__name__} between {url1} and {url2} is {metric(html1, html2):.2f}')
            successes += 1
            total_time += (end - start)
        print(f'Total time for {metric.__name__} is {total_time:.2f}')
        print(f'Successes: {successes}')
        print(f'Average time for {metric.__name__} is {total_time / successes:.2f}')
        print()

print("Body limit:", LIMIT)
# print nice output
similarity = radoy_header_ratio(html1, html2)
print(f'Radoy Similarity between {url1} and {url2} is {similarity:.2f}')

similarity = levenshtein_header_similarity(html1, html2)
print(f'Header Similarity between {url1} and {url2} is {similarity:.2f}')

similarity = binary_bag_of_tree_paths_similarity(html1, html2)
print(f'BOTP Similarity with binary indicator between {url1} and {url2} is {similarity:.2f}')

similarity = bag_of_tree_paths_similarity(html1, html2, )
print(f'BOTP Similarity with frequencies between {url1} and {url2} is {similarity:.2f}')

similarity = binary_bag_of_xpaths_similarity(html1, html2)
print(f'BOXP Similarity with binary indicator between {url1} and {url2} is {similarity:.2f}')

similarity = bag_of_xpaths_similarity(html1, html2)
print(f'BOXP Similarity with frequencies between {url1} and {url2} is {similarity:.2f}')

similarity = levenshtein_ratio(html1, html2)
print(f'Levenshtein Similarity between {url1} and {url2} is {similarity:.2f}')
