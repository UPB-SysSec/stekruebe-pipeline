import json
from typing import Any, Union

__all__ = ["Filter"]


def DEBUG(*args, **kwargs):
    pass


# DEBUG = print


class JsonPath:
    def __init__(self, path: str = None):
        if isinstance(path, str):
            if path == "":
                self.items = ()
            else:
                self.items = tuple(path.split("."))
        elif isinstance(path, (tuple, list)):
            self.items = tuple(path)
        elif path is None:
            self.items = ()
        else:
            raise TypeError(f"Invalid path type {type(path)}")

    @property
    def isEmpty(self):
        return not self.items

    def join(self, other):
        return JsonPath(self.items + (other,))

    def __truediv__(self, other):
        return self.join(other)

    def __getitem__(self, idx):
        if isinstance(idx, slice):
            return JsonPath(self.items[idx])
        elif isinstance(idx, int):
            return self.items[idx]
        else:
            raise TypeError(f"Invalid index type {type(idx)}")

    def __repr__(self) -> str:
        return f"JsonPath({'.'.join(self.items)})"


class JsonFilterTree:
    def __init__(self, object, parent: "JsonFilterTree" = None, path: JsonPath = ""):
        if isinstance(path, str):
            path = JsonPath(path)
        self.path = path  # only used for debugging

        self.children: Union[dict[str, "JsonFilterTree"], list["JsonFilterTree"], Any] = None
        self.parent = parent
        self._keep = True

        if isinstance(object, dict):
            self.children = {}
            for k, v in object.items():
                self.children[k] = JsonFilterTree(v, self, path / k)
        elif isinstance(object, list):
            self.children = [JsonFilterTree(v, self, path) for v in object]
        else:
            self.value = object

    @property
    def keep(self):
        return self._keep

    def _propagate_keep_up(self, value):
        if self._keep == value:
            return
        self._keep = value
        if self.parent:
            self.parent._propagate_keep_up(value)

    def _propagate_keep_down(self, value):
        if self._keep == value:
            return
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
        # DEBUG("+" if value else "-", self.path)
        # propagate downwards. More specific rules should follow later on
        self._propagate_keep_down(value)
        if value and self.parent:
            # only propagate True up, so that we do not lose our parent
            # False should not be propagated up, as this would always kill the root
            self.parent._propagate_keep_up(value)

    def set_keep(self, pattern: JsonPath, value: bool):
        # DEBUG(f"set_keep path={self.path} pattern={pattern} value={value}")
        if pattern.isEmpty:
            self.keep = value
            return

        if isinstance(self.children, list):
            for child in self.children:
                child.set_keep(pattern, value)
            return

        if not isinstance(self.children, dict):
            # native value, do not proceed
            return

        l, r = pattern[0], pattern[1:]

        if l == "*":
            for child in self.children.values():
                child.set_keep(pattern, value)
                child.set_keep(r, value)
            return

        if l in self.children:
            self.children[l].set_keep(r, value)

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

    def apply(self, item, output_type=...):
        if isinstance(item, str):
            raise TypeError("Filter.apply() does not support str input; maybe use apply_str")

        item_tree = JsonFilterTree(item)
        for pattern in self.filters:
            inclusion_pattern = pattern.startswith("!")
            # DEBUG(pattern)
            if inclusion_pattern:
                pattern = pattern[1:]
            item_tree.set_keep(JsonPath(pattern), inclusion_pattern)
        return item_tree.flatten()

    def apply_str_out(self, item):
        return json.dumps(self.apply(item))

    def apply_str_in_str_out(self, item: str):
        return json.dumps(self.apply(json.loads(item)))

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
        "data.https-tls1_3.result.*",
        "!data.https-tls1_3.result.response.request.tls_log",
        "*.handshake_log.server_certificates.*.parsed",
    )
    filter = Filter(*PATHS_TO_FILTER)

    import json, time

    with open("test.json") as f:
        obj = json.load(f)

    print(len(str(obj)))
    start = time.time()
    filtered = filter.apply(obj)
    diff = time.time() - start
    print(diff)
    # performance target
    PERFORMANCE_TARGET = 1 / 3000  # 3k items per second
    N = 20
    if diff > PERFORMANCE_TARGET:
        print("[ ! ] Warning: Filtering seems too slow")
        print(f"[ ! ] Got  {diff:.5f}s")
        print(f"[ ! ] Need {PERFORMANCE_TARGET:.5f}s")
        print(f"[ ! ] Is {diff / PERFORMANCE_TARGET:.1f}x too slow")
        print(f"[ ! ] Reevaluating with {N} iterations")
        start = time.time()
        for _ in range(N):
            filter.apply(obj)
        diff = (time.time() - start) / N

    if diff > PERFORMANCE_TARGET:
        print("[!!!] Warning: Filtering is too slow")
        print(f"[!!!] Got  {diff:.5f}s")
        print(f"[!!!] Need {PERFORMANCE_TARGET:.5f}s")
        print(f"[!!!] Is {diff / PERFORMANCE_TARGET:.1f}x too slow")
        if not True:
            import cProfile

            start = time.time()
            cProfile.runctx("filter.apply(obj)", globals(), locals(), filename="/tmp/filter.prof")
            prof_diff = time.time() - start
            print(f"Runtime during profile  {prof_diff:.5f}s")
            PROF_PERFORMANCE_TARGET = PERFORMANCE_TARGET * (prof_diff / diff)
            print(f"Profiled runtime target {PROF_PERFORMANCE_TARGET:.5f}s (x{prof_diff / diff:.1f})")
    print(len(str(filtered)))
    # print(filtered)

    _check(filtered, "data.https-tls1_3.result.response", bool)
    _check_not(filtered, "data.https-tls1_3.result.response.protocol")
    _check(filtered, "data.https-tls1_3.result.response.request.tls_log.handshake_log.server_hello", bool)
    _check(
        filtered,
        "data.https-tls1_3.result.response.request.tls_log.handshake_log.server_certificates.certificate.raw",
        bool,
    )
    _check_not(
        filtered,
        "data.https-tls1_3.result.response.request.tls_log.handshake_log.server_certificates.certificate.parsed",
    )


if __name__ == "__main__":
    _test_list()
    _test_allow_under_wildcard()
    _test_complex()
    _test_real()
