import re

TITLE_RE = re.compile(r"<title[^>]*>(.*)</title>", re.IGNORECASE | re.DOTALL)
HEADING_RE = re.compile(r"<h[1-3][^>]*>(.*)</h[1-3]>", re.IGNORECASE | re.DOTALL)
META_TITLE_RE = re.compile(r'<meta[^>]*name="[^"]*title"[^>]*content="([^"]+)"', re.IGNORECASE | re.DOTALL)


def extract_title(body: str) -> str:
    title = TITLE_RE.search(body)
    if title is not None:
        return "[title]" + title.group(1)
    if "<" not in body and len(body) < 1000:
        # no html tags, probably plaintext
        return "[body]" + body
    meta = META_TITLE_RE.search(body)
    if meta is not None:
        return "[meta]" + meta.group(1)
    heading = HEADING_RE.search(body)
    if heading is not None:
        return "[heading]" + heading.group(1)
    return None


assert extract_title("<title>test</title>") == "test"
assert extract_title("asd <titLe>test</titLe>") == "test"
assert extract_title('asd <titLe foo="bar">test</titLe>') == "test"
assert extract_title('asd <titLe foo="bar">\ntest\n</titLe>') == "\ntest\n"
assert (
    extract_title('<!DOCTYPE html>\n<html><head><meta name="robots" content="noindex,nofollow"><title>exchange</title>')
    == "exchange"
)
