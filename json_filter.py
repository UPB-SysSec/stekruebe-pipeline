import fnmatch
from typing import Any, Union

__all__ = ["Filter"]


class JsonFilterTree:
    def __init__(self, object, parent: "JsonFilterTree" = None, path: str = ""):
        self.children: Union[dict[str, "JsonFilterTree"], list["JsonFilterTree"], Any] = None
        self.parent = parent
        self.path = path
        self._keep = True
        if isinstance(object, dict):
            self.children = {}
            for k, v in object.items():
                self.children[k] = JsonFilterTree(v, self, (path + "." if path else "") + k)
        elif isinstance(object, list):
            self.children = [JsonFilterTree(v, self, path) for v in object]
        else:
            self.value = object

    @property
    def keep(self):
        return self._keep

    def _propagate_keep_up(self, value):
        self._keep = value
        if self.parent:
            self.parent._propagate_keep_up(value)

    def _propagate_keep_down(self, value):
        self._keep = value
        if isinstance(self.children, dict):
            for child in self.children.values():
                child._propagate_keep_down(value)
        elif isinstance(self.children, list):
            for child in self.children:
                child._propagate_keep_down(value)

    @keep.setter
    def keep(self, value):
        assert isinstance(value, bool)
        self._keep = value
        # print("+" if value else "-", self.path)
        # propagate downwards. More specific rules should follow later on
        self._propagate_keep_down(value)
        if value:
            # only propagate True up, so that we do not lose our parent
            # False should not be propagated up, as this would always kill the root
            self._propagate_keep_up(value)

    def paths(self, *, _current_prefix=None):
        if _current_prefix:
            yield _current_prefix
        if isinstance(self.children, dict):
            for k, v in self.children.items():
                _new_prefix = _current_prefix + "." + k if _current_prefix else k
                yield from v.paths(_current_prefix=_new_prefix)
        elif isinstance(self.children, list):
            for v in self.children:
                yield from v.paths(_current_prefix=_current_prefix)

    def set_keep(self, path: str, value: bool):
        if path == "":
            self.keep = value
        else:
            if isinstance(self.children, dict):
                if "." in path:
                    l, r = path.split(".", 1)
                else:
                    l, r = path, ""

                if l in self.children:
                    self.children[l].set_keep(r, value)
            elif isinstance(self.children, list):
                for child in self.children:
                    child.set_keep(path, value)

    def flatten(self):
        if isinstance(self.children, dict):
            return {k: v.flatten() for k, v in self.children.items() if v.keep}
        elif isinstance(self.children, list):
            return [v.flatten() for v in self.children if v.keep]
        else:
            return self.value


class Filter:
    def __init__(self, *filters: str):
        self.filters = filters

    def apply(self, item):
        item_tree = JsonFilterTree(item)
        for pattern in self.filters:
            inclusion_pattern = pattern.startswith("!")
            # print(pattern)
            if inclusion_pattern:
                pattern = pattern[1:]
                # would be nicer if we could apply the pattern directly, but then we need to handle wildcards ourselves...
            for path in item_tree.paths():
                if fnmatch.fnmatch(path, pattern):
                    item_tree.set_keep(path, inclusion_pattern)
        return item_tree.flatten()

    def __call__(self, item):
        return self.apply(item)


def _check(item, path, expected_value="value"):
    while path:
        if isinstance(item, dict):
            if "." in path:
                k, path = path.split(".", 1)
            else:
                k, path = path, ""
            item = item[k]
        else:
            for it in item:
                _check(it, path, expected_value)
            return
    if callable(expected_value):
        assert expected_value(item)
    else:
        assert item == expected_value


def _check_not(item, path):
    try:
        _check(item, path, lambda x: False)
        assert False
    except KeyError:
        pass


def _test_complex():
    filter = Filter(
        "a.b.*",  # 1
        "!a.b.c",  # 2
        "!a.b.c.*",  # 2+
        "a.b.c.d",  # 3
        "b.*.c",  # 4
        "*.r",  # 5
    )
    original = {
        "a": {  # survive
            "b": {  # survive
                "c": {  # survive (2)
                    "d": "value",  # delete (3)
                    "e": "value",  # survive(2+)
                },
                "e": "value",  # delete (1)
            },
        },
        "b": {  # survive
            "c": {  # survive
                "d": "value",  # survive
            },
            "x": {  # survive
                "c": "value",  # delete (4)
            },
            "r": "value",  # delete (5)
        },
    }
    item = filter.apply(original)
    _check(item, "a.b.c", lambda x: isinstance(x, dict))
    _check_not(item, "a.b.c.d")
    _check(item, "a.b.c.e")
    _check_not(item, "a.b.e")
    _check(item, "b.c.d")
    _check(item, "b.x", {})
    _check_not(item, "b.x.c")
    _check_not(item, "b.r")


def _test_allow_under_wildcard():
    filter = Filter(
        "a.b.*",
        "!a.b.c.d.e",
    )
    original = {
        "a": {
            "b": {
                "c": {
                    "d": {
                        "e": "value",
                        "x": "value",
                    },
                    "x": "value",
                },
                "r": "value",
            },
        },
    }
    filtered = filter.apply(original)
    _check(filtered, "a.b.c.d.e")
    _check_not(filtered, "a.b.r")
    _check_not(filtered, "a.b.c.d.x")
    _check_not(filtered, "a.b.c.x")


def _test_list():
    filter = Filter(
        "a.b.c.d",
    )
    original = {
        "a": {
            "b": [
                {"c": {"d": "value"}},
                {"c": {"d": "value"}},
            ],
        },
    }
    filtered = filter.apply(original)
    _check(filtered, "a.b.c", {})
    _check_not(filtered, "a.b.c.d")
    assert "c" in filtered["a"]["b"][0]
    assert "c" in filtered["a"]["b"][1]
    assert "d" not in filtered["a"]["b"][0]["c"]
    assert "d" not in filtered["a"]["b"][1]["c"]


def _test_real():
    PATHS_TO_FILTER = (
        "data.http.result.*",
        "!data.http.result.response.request.tls_log",
        "*.handshake_log.server_certificates.*.parsed",
    )
    filter = Filter(*PATHS_TO_FILTER)

    import json

    with open("test.json") as f:
        obj = json.load(f)

    print(len(str(obj)))
    filtered = filter.apply(obj)
    print(len(str(filtered)))
    # print(filtered)

    _check(filtered, "data.http.result.response", bool)
    _check_not(filtered, "data.http.result.response.protocol")
    _check(filtered, "data.http.result.response.request.tls_log.handshake_log.server_hello", bool)
    _check(
        filtered, "data.http.result.response.request.tls_log.handshake_log.server_certificates.certificate.raw", bool
    )
    _check_not(
        filtered, "data.http.result.response.request.tls_log.handshake_log.server_certificates.certificate.parsed"
    )


if __name__ == "__main__":
    _test_list()
    _test_allow_under_wildcard()
    _test_complex()
    _test_real()
