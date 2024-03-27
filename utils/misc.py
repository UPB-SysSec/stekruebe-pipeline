import re

REGEXES = {
    "title": re.compile(r"<title[^>]*>(.*)</title>", re.IGNORECASE | re.DOTALL),
    "meta_title": re.compile(
        r'<meta[^>]*(?:name|property)="[^"]*title"[^>]*content="([^"]+)"', re.IGNORECASE | re.DOTALL
    ),
    "meta_desc": re.compile(
        r'<meta[^>]*(?:name|property)="[^"]*description"[^>]*content="([^"]+)"', re.IGNORECASE | re.DOTALL
    ),
    "heading": re.compile(r"<h[1-3][^>]*>(.*)</h[1-3]>", re.IGNORECASE | re.DOTALL),
}


def extract_title(body: str) -> str:
    for key, regex in REGEXES.items():
        match = regex.search(body)
        if match is not None:
            return f"[{key}]{match.group(1)}"
    return None


assert extract_title("<title>test</title>") == "[title]test"
assert extract_title("asd <titLe>test</titLe>") == "[title]test"
assert extract_title('asd <titLe foo="bar">test</titLe>') == "[title]test"
assert extract_title('asd <titLe foo="bar">\ntest\n</titLe>') == "[title]\ntest\n"
assert (
    extract_title('<!DOCTYPE html>\n<html><head><meta name="robots" content="noindex,nofollow"><title>exchange</title>')
    == "[title]exchange"
)
assert (
    extract_title('<meta property="og:title" content="Ставки на спорт в букмекерской конторе Betera в Беларуси">')
    == "[meta_title]Ставки на спорт в букмекерской конторе Betera в Беларуси"
)
