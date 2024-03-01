import json

v4lens = []
v6lens = []
anylens = []

with open("out/0_resolved.json") as f:
    for ln in f:
        resolved = json.loads(ln)
        data = resolved.get("data", {})
        v4 = data.get("ipv4_addresses", [])
        v6 = data.get("ipv6_addresses", [])
        v4lens.append(len(v4))
        v6lens.append(len(v6))
        anylens.append(len(v4) + len(v6))


def analyze(lenlist: list[int]):
    yield "avg", sum(lenlist) / len(lenlist)
    yield "max", max(lenlist)
    yield "min", min(lenlist)
    # percentiles
    lenlist.sort()
    for p in [50, 75, 90, 95, 99]:
        yield f"p{p}", lenlist[int(len(lenlist) * p / 100)]
    for i in range(-9, 0):
        yield f"{i}", lenlist[i]


v4stats = dict(analyze(v4lens))
v6stats = dict(analyze(v6lens))
anystats = dict(analyze(anylens))

assert v4stats.keys() == v6stats.keys() == anystats.keys()

table = [("", "v4", "v6", "any")]
for k in v4stats:
    table.append((k, v4stats[k], v6stats[k], anystats[k]))


table.insert(1, ("-" * 9 + ":",) * 4)
for row in table:
    ln = "|"
    for cell in row:
        if isinstance(cell, float):
            ln += f"{cell:10.2f}"
        elif isinstance(cell, int):
            ln += f"{cell:10d}"
        elif isinstance(cell, str):
            ln += f"{cell:>10s}"
        else:
            raise ValueError(f"Unknown type: {type(cell)}")
        ln += "|"
    print(ln)
