import json
from enum import Enum
import functools


class Encoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Enum):
            return o.name

        if hasattr(o, "__dict__"):
            return o.__dict__
        return super().default(o)


@functools.wraps(json.dump)
def dump(obj, fp, **kwargs):
    kwargs.setdefault("cls", Encoder)
    return json.dump(obj, fp, **kwargs)


@functools.wraps(json.dumps)
def dumps(obj, **kwargs):
    kwargs.setdefault("cls", Encoder)
    return json.dumps(obj, **kwargs)


@functools.wraps(json.load)
def load(fp, **kwargs):
    return json.load(fp, **kwargs)


@functools.wraps(json.loads)
def loads(s, **kwargs):
    return json.loads(s, **kwargs)


if __name__ == "__main__":
    from dataclasses import dataclass

    class A:
        def __init__(self, a):
            self.a = a

    class B(Enum):
        A = 1
        B = 2

    @dataclass
    class C:
        a: A
        b: B

    c = C(A(1), B.A)
    print(dumps(c))
