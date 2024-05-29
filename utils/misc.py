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

assert extract_title(
    '''
    }.teaser-chevron::after{background-image:url("data:image/svg+xml;utf8,<svg version='1.1' viewBox='0 0 7 12' xmlns='http://www.w3.org/2000/svg'><title>chevron-right</title><desc>Created with Sketch.</desc><g transform='translate(-593 -22)' fill='none' fill-rule='evenodd'><g fill='#1773C7'><g transform='translate(520 22)'><path d='m79.747 6.5641l-5.3529 5.147c-0.15956 0.15359-0.36523 0.22997-0.5707 0.22997-0.21618 0-0.43194-0.084617-0.59356-0.25282-0.31541-0.32776-0.30512-0.84906 0.022853-1.1643l4.7355-4.5535-4.7355-4.5535c-0.32797-0.3152-0.33826-0.8365-0.022853-1.1643 0.315-0.32797 0.83629-0.33826 1.1643-0.022853l5.3529 5.147c0.16162 0.15523 0.25282 0.36956 0.25282 0.59356 0 0.224-0.091206 0.43832-0.25282 0.59356z'/></g></g></g></svg>");')
    ''') == "[title]chevron-right"