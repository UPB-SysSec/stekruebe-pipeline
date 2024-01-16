# A hopefully more configurable way to run our whole pipeline
import csv
import ipaddress
import json
import logging
import os
import os.path as op
import subprocess
import threading
import time
from abc import ABC, abstractmethod
from enum import Enum
from itertools import chain
from random import shuffle
from select import select
from typing import Any, Generic, TypeVar

from json_filter import Filter as JsonFilter


class FileFormat(Enum):
    JSON = [".json"]
    CSV = [".csv"]
    TXT = [".txt", ".ips"]

    @classmethod
    def from_filename(cls, filename: str):
        filename = filename.lower()
        extension = op.splitext(filename)[1]
        for fmt in cls:
            if extension in fmt.value:
                return fmt
        raise ValueError(f"Unknown file format for {filename!r}")

    def dump_to_file(self, content, filename):
        with open(filename, "w") as f:
            if self == FileFormat.JSON:
                json.dump(content, f)
            elif self == FileFormat.CSV:
                csv.writer(f).writerows(content)
            elif self == FileFormat.TXT:
                for ln in content:
                    f.write(ln)
                    f.write("\n")
            else:
                raise ValueError(f"Unknown file format {self}")

    def parse_from_file(self, filename):
        with open(filename) as f:
            if self == FileFormat.JSON:
                return json.load(f)
            elif self == FileFormat.CSV:
                return list(csv.reader(f))
            elif self == FileFormat.TXT:
                return f.read().splitlines()
            else:
                raise ValueError(f"Unknown file format {self}")


OUTPUTS = TypeVar("OUTPUTS")


class _Stats:
    def __init__(self, filename: str):
        self.filename = filename

    def store(self, stage_name: str, name: str, data: Any):
        with open(self.filename, "a", newline="") as f:
            csv.writer(f).writerow([stage_name, name, json.dumps(data)])


class Stage(ABC, Generic[OUTPUTS]):
    def __init__(self, name, stats: _Stats) -> None:
        self.logger = logging.getLogger(__name__ + "." + name)
        self.name = name
        self.stats = stats

    def _store_stat(self, name: str, data: Any):
        if self.stats:
            self.stats.store(self.name, name, data)

    @abstractmethod
    def run_stage(self, *args, **kwargs) -> OUTPUTS:
        ...

    def __call__(self, *args, **kwargs) -> Any:
        self.logger.info(f"Starting")
        start = time.time()
        res = self.run_stage(*args, **kwargs)
        end = time.time()
        self._store_stat("start", start)
        self._store_stat("end", end)
        self._store_stat("runtime", end - start)

        res_len = None
        if isinstance(res, list):
            res_len = len(res)
        elif isinstance(res, (int, float)):
            res_len = res
        else:
            raise ValueError(f"Unexpected output type {type(res)}")

        self.logger.info(f"Took {end - start:.2f}s - resulted in {res_len} items")
        self._store_stat("output_size", res_len)

        return res


class CacheableStage(Stage[OUTPUTS]):
    def __init__(self, name, stats: _Stats, cache_as_format: FileFormat = ...) -> None:
        super().__init__(name, stats)
        self.cache_as_format = cache_as_format

    def write_output_file(self, results: OUTPUTS, output_file):
        if self.cache_as_format is ...:
            format = FileFormat.from_filename(output_file)
        else:
            format = self.cache_as_format
        format.dump_to_file(results, output_file)

    def load_output_file(self, output_file) -> OUTPUTS:
        if self.cache_as_format is ...:
            format = FileFormat.from_filename(output_file)
        else:
            format = self.cache_as_format
        return format.parse_from_file(output_file)

    def __call__(self, *args, cache_file, cache_write=True, cache_load=True, dry_run=False, **kwargs):
        if cache_file and op.isfile(cache_file):
            if cache_load:
                self.logger.info(f"Loading results from {cache_file}")
                return self.load_output_file(cache_file)
            if cache_write:
                raise ValueError(
                    f"Cache file {cache_file!r} already exists, but cache_load is False. Rejeting to overwrite."
                )

        if dry_run:
            self.logger.info("Dry run. Skipping.")
            return None

        results = super().__call__(*args, **kwargs)
        if cache_file and cache_write:
            self.logger.info(f"Storing results into {cache_file}")
            self.write_output_file(results, cache_file)
        return results


class FileLineReader(Stage[list[str]]):
    def __init__(self, name, stats, filepath, strip_lines=True, n_lines=None) -> None:
        super().__init__(name, stats)
        self.filepath = filepath
        self.strip_lines = strip_lines
        self.n_lines = n_lines

    def _run_stage(self):
        with open(self.filepath) as f:
            for i, line in enumerate(f):
                if self.n_lines is not None and i >= self.n_lines:
                    return
                if self.strip_lines:
                    line = line.strip()
                yield line

    def run_stage(self):
        return list(self._run_stage())


class SimpleSubprocessStage(CacheableStage[list[str]]):
    def __init__(self, name, stats, command, *args, cache_as_format: FileFormat = ..., **kwargs) -> None:
        super().__init__(name, stats, cache_as_format=cache_as_format)
        self.command = command
        self.args = args
        self.kwargs = kwargs

    def run_stage(self, input_string_list: list[str] = None) -> list[str]:
        cmd = [self.command, *self.args]
        proc_input = None
        if input_string_list is not None:
            proc_input = "\n".join(input_string_list).encode()
        proc = subprocess.run(cmd, input=proc_input, capture_output=True, **self.kwargs)
        try:
            proc.check_returncode()
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command {cmd!r} failed with exit code {e.returncode}")
            self.logger.error(f"Stderr: {proc.stderr.decode()}")
            raise e
        return proc.stdout.decode().splitlines()


class ZDNS(SimpleSubprocessStage):
    def __init__(self, stats, *args, name_overwrite="ZDNS", **kwargs) -> None:
        super().__init__(name_overwrite, stats, *args, **kwargs)

    def run_stage(self, input_string_list: list[str] = None) -> list[str]:
        start = time.time()
        ret = super().run_stage(input_string_list)
        end = time.time()
        self._store_stat("zdns runtime", end - start)

        start = time.time()
        status_counts = {}
        no_ips = 0
        only_v4 = 0
        only_v6 = 0
        both = 0
        for ln in ret:
            item = json.loads(ln)
            status = item.get("status", "N/A")
            if status not in status_counts:
                status_counts[status] = 0
            status_counts[status] += 1
            if status == "NOERROR":
                data = item.get("data", {})
                if data.get("ipv4_addresses"):
                    if data.get("ipv6_addresses"):
                        both += 1
                    else:
                        only_v4 += 1
                elif data.get("ipv6_addresses"):
                    only_v6 += 1
                else:
                    no_ips += 1
        end = time.time()
        self._store_stat("zdns postprocess runtime", end - start)

        self._store_stat("status_counts", status_counts)
        self._store_stat("no_ips", no_ips)
        self._store_stat("only_v4", only_v4)
        self._store_stat("only_v6", only_v6)
        self._store_stat("both_v4_and_v6", both)
        return ret


class BlocklistFilter(CacheableStage[list[str]]):
    def __init__(self, name, stats: _Stats, blocklist_file) -> None:
        super().__init__(name, stats)
        self.blocklist_file = blocklist_file

    def _parse_blocklist(self) -> list[ipaddress.ip_network]:
        start = time.time()
        with open(self.blocklist_file) as f:
            for ln in f:
                yield ipaddress.ip_network(ln.strip())
        end = time.time()
        self._store_stat("blocklist_load_time", end - start)

    def _run_stage(self, ip_addresses: list[str]):
        blocklist = list(self._parse_blocklist())

        def is_blocked(ip: str):
            addr = ipaddress.ip_address(ip)
            for net in blocklist:
                if addr in net:
                    return True
            return False

        start = time.time()
        for ip in ip_addresses:
            if not is_blocked(ip):
                yield ip
        end = time.time()
        self._store_stat("blocklist_filter_time", end - start)

    def run_stage(self, ip_addresses: list[str]):
        ret = self._run_stage(ip_addresses)
        ret = list(set(ret))
        shuffle(ret)
        return ret


class MergeUniq(CacheableStage[list[str]]):
    def __init__(self, stats: _Stats) -> None:
        super().__init__("MergeUniq", stats)

    def run_stage(self, *lists: list[str]) -> list[str]:
        all_items = set()
        for lst in lists:
            all_items.update(lst)
        return sorted(all_items)


class MapIPsToDomains(CacheableStage[list[tuple[str, str]]]):
    def __init__(self, stats: _Stats) -> None:
        super().__init__("MapIPsToDomains", stats)

    def _run_stage(self, resolved_domains: list, ips: list[str]):
        ips_to_domains = {}
        for line in resolved_domains:
            item = json.loads(line)
            domanin = item.get("name")
            for ip in chain(
                item.get("data", {}).get("ipv4_addresses", []),
                item.get("data", {}).get("ipv6_addresses", []),
            ):
                if ip not in ips_to_domains:
                    ips_to_domains[ip] = []
                ips_to_domains[ip].append(domanin)

        for ip in ips:
            if ip in ips_to_domains:
                for domain in ips_to_domains[ip]:
                    yield ip, domain
            else:
                raise ValueError(f"No domain for {ip}")

    def run_stage(self, resolved_domains: list, ips: list[str]):
        return list(self._run_stage(resolved_domains, ips))


class ZgrabRunner(Stage[int]):
    def __init__(
        self,
        name,
        stats: _Stats,
        executable: str,
        output_file: str,
        out_filter: JsonFilter,
        *args,
    ) -> None:
        super().__init__(name, stats)
        self.executable = executable
        self.args = args

        self.connections_per_host = 1
        self.out_filter = out_filter
        self.output_file = output_file
        for arg in self.args:
            if arg.startswith("--connections-per-host="):
                self.connections_per_host = int(arg.split("=")[1])

    def _send_targets(self, proc: subprocess.Popen, ip_and_hosts: list[tuple[str, str]]):
        for ip, host in ip_and_hosts:
            proc.stdin.write(f"{ip},{host}\n".encode())
        proc.stdin.flush()
        proc.stdin.close()
        self.logger.info(f"Sent {len(ip_and_hosts)} targets to zgrab")

    def run_stage(self, ip_and_hosts: list[tuple[str, str]]) -> int:
        if op.isfile(self.output_file):
            self.logger.warning(f"Output file {self.output_file!r} already exists. Skipping.")
            return -1

        total = 0
        stderr = b""
        with (
            open(self.output_file, "w") if self.output_file else open(os.devnull, "w") as fo,
            subprocess.Popen(
                [self.executable, *self.args],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ) as proc,
        ):
            inputthread = threading.Thread(target=self._send_targets, args=(proc, ip_and_hosts), daemon=True)
            inputthread.start()
            while returncode := proc.poll() is None:
                # _, ready, _ = select([], [proc.stdout, proc.stderr], [])
                for line in proc.stdout:
                    total += 1
                    item = json.loads(line.decode().strip())
                    item = self.out_filter(item)
                    if item:
                        json.dump(item, fo)
                        fo.write("\n")

            stderr += proc.stderr.read()

        if returncode:
            raise subprocess.CalledProcessError(self.returncode, self.args, self.stdout, self.stderr)
        status_line = stderr.decode().strip().split("\n")[-1]
        status = json.loads(status_line)
        self._store_stat("zgrab_status", status)
        return total / self.connections_per_host


class PostProcessZGrab(Stage[None]):
    def __init__(self, stats: _Stats, connections_per_host: int) -> None:
        super().__init__("Postprocess Zgrab", stats)
        self.connections_per_host = connections_per_host

    def run_stage(self, zgrab_out_file: str, outfile: str) -> None:
        if op.isfile(outfile):
            self.logger.warning(f"Output file {outfile!r} already exists. Skipping.")
            return -1

        with open(zgrab_out_file) as f_in, open(outfile, "w") as f_out:
            f_in.seek(0, os.SEEK_END)
            total = f_in.tell()
            f_in.seek(0)

            zgrab_results = {}
            handled = set()

            while ln := f_in.readline():
                item = json.loads(ln)
                ip = item["ip"]
                domain = item["domain"]

                zgrab_result = {}
                try:
                    zgrab_result["ticket"] = item["data"]["tls"]["result"]["handshake_log"]["session_ticket"]
                except KeyError:
                    zgrab_result["ticket"] = None
                try:
                    zgrab_result["status"] = item["data"]["tls"]["status"]
                except KeyError:
                    zgrab_result["status"] = None

                key = (ip, domain)
                if key not in zgrab_results:
                    assert key not in handled
                    zgrab_results[key] = []

                zgrab_results[key].append(zgrab_result)

                if len(zgrab_results[key]) >= self.connections_per_host:
                    json.dump({"ip": ip, "domain": domain, "results": zgrab_results[key]}, f_out)
                    f_out.write("\n")
                    del zgrab_results[key]
                    handled.add(key)
                    if len(handled) % 10_000 == 0:
                        print(
                            f"Handled: {len(handled):7d} ({100*f_in.tell()/total:6.2f}%) | Currently open: {len(zgrab_results):7d}"
                        )
            assert not zgrab_results, zgrab_results
            return len(handled)


def main(TRANCO_NUM=None, DRY_RUN=False):
    class CONST:
        IPv6SRC = "2001:638:502:28::51"
        ZGRAB_CONNECTIONS_PER_HOST = 5

    class EXEUTABLES:
        JQ = "jq"
        ZDNS = "/root/zdns/zdns"
        ZMAP4 = "/root/zmap/src/zmap"
        ZMAP6 = "/root/zmapv6/src/zmap"
        ZGRAB = "/data/cdn_ticket/zgrab2"

    if not op.isdir("out"):
        os.mkdir("out")

    class FILES:
        TRANCO = "tranco_7X8NX.csv"
        BLOCKLIST_4 = "/data/Crawling-Blacklist/blacklist.txt"
        BLOCKLIST_6 = "/data/Crawling-Blacklist/blacklist-ipv6.txt"

        RESOLVED_DOMAINS = "out/0_resolved.json"

        RESOLVED_IPS4 = "out/1_resolved_v4.ips"
        RESOLVED_IPS6 = "out/1_resolved_v6.ips"

        FILTERED_4_IPLIST = "out/2_resolved_filtered_v4.ips"
        FILTERED_6_IPLIST = "out/2_resolved_filtered_v6.ips"

        HTTPS_4_IPLIST = "out/3_https_hosts_v4.ips"
        HTTPS_6_IPLIST = "out/3_https_hosts_v6.ips"

        MERGED_IP_LIST = "out/4_merged.ips"
        MERGED_HOST_LIST = "out/5_merged.csv"
        ZGRAB_OUT = "out/6_zgrab.json"
        ZGRAB_MERGED_OUT = "out/7_merged_zgrab.json"

    stats = _Stats("out/stats.csv")

    ZGRAB_FILTER = JsonFilter(
        "data.http.result.*",
        "!data.http.result.response.request.tls_log",
        "*.handshake_log.server_certificates.*.parsed",
    )

    class STAGES:
        TRANCO = FileLineReader("ReadTranco", stats, FILES.TRANCO, n_lines=TRANCO_NUM)
        ZDNS = ZDNS(
            stats,
            EXEUTABLES.ZDNS,
            "--alexa",
            "alookup",
            "--ipv4-lookup",
            "--ipv6-lookup",
            cache_as_format=FileFormat.TXT,
        )
        JQ4 = SimpleSubprocessStage("JQ4", stats, EXEUTABLES.JQ, "-r", ".data.ipv4_addresses | select(. != null) | .[]")
        JQ6 = SimpleSubprocessStage("JQ6", stats, EXEUTABLES.JQ, "-r", ".data.ipv6_addresses | select(. != null) | .[]")
        BLOCKLIST4 = BlocklistFilter("Blocklist4", stats, FILES.BLOCKLIST_4)
        BLOCKLIST6 = BlocklistFilter("Blocklist6", stats, FILES.BLOCKLIST_6)
        ZMAP4 = SimpleSubprocessStage(
            "ZMAP4",
            stats,
            EXEUTABLES.ZMAP4,
            "-b",
            FILES.BLOCKLIST_4,
            "-p",
            "443",
            "-w",
            FILES.FILTERED_4_IPLIST,
        )
        ZMAP6 = SimpleSubprocessStage(
            "ZMAP6",
            stats,
            EXEUTABLES.ZMAP6,
            "-M",
            "ipv6_tcp_synscan",
            "-p",
            "443",
            "--ipv6-source-ip",
            CONST.IPv6SRC,
            "--ipv6-target-file",
            FILES.FILTERED_6_IPLIST,
        )
        MERGE_UNIQ = MergeUniq(stats)
        MAP_IPS_TO_DOMAINS = MapIPsToDomains(stats)
        ZGRAB = ZgrabRunner(
            "Zgrab",
            stats,
            EXEUTABLES.ZGRAB,
            FILES.ZGRAB_OUT,
            ZGRAB_FILTER,
            "multiple",
            "-c",
            "get-ticket-for-grouping.ini",
            f"--connections-per-host={CONST.ZGRAB_CONNECTIONS_PER_HOST}",
        )
        PP_ZGRAB = PostProcessZGrab(stats, CONST.ZGRAB_CONNECTIONS_PER_HOST)

    tranco = STAGES.TRANCO()
    resolved_hosts = STAGES.ZDNS(input_string_list=tranco, cache_file=FILES.RESOLVED_DOMAINS, dry_run=DRY_RUN)
    del tranco
    IPv4s = STAGES.JQ4(resolved_hosts, cache_file=FILES.RESOLVED_IPS4)
    IPv6s = STAGES.JQ6(resolved_hosts, cache_file=FILES.RESOLVED_IPS6)
    IPv4s = STAGES.BLOCKLIST4(IPv4s, cache_file=FILES.FILTERED_4_IPLIST)
    IPv6s = STAGES.BLOCKLIST6(IPv6s, cache_file=FILES.FILTERED_6_IPLIST)
    IPv4s = STAGES.ZMAP4(cache_file=FILES.HTTPS_4_IPLIST, dry_run=DRY_RUN)
    IPv6s = STAGES.ZMAP6(cache_file=FILES.HTTPS_6_IPLIST, dry_run=DRY_RUN)
    IPs = STAGES.MERGE_UNIQ(IPv4s, IPv6s, cache_file=FILES.MERGED_IP_LIST)
    del IPv4s, IPv6s
    ip_and_hosts = STAGES.MAP_IPS_TO_DOMAINS(resolved_hosts, IPs, cache_file=FILES.MERGED_HOST_LIST, dry_run=DRY_RUN)
    del resolved_hosts
    if not DRY_RUN:
        STAGES.ZGRAB(ip_and_hosts)
    STAGES.PP_ZGRAB(FILES.ZGRAB_OUT, FILES.ZGRAB_MERGED_OUT)


def test_zdns():
    if not op.isdir("out_test"):
        os.mkdir("out_test")
    stats = _Stats("out_test/stats.csv")

    class EXEUTABLES:
        ZDNS = "/root/zdns/zdns"

    class FILES:
        TRANCO = "tranco_7X8NX.csv"

    tranco = FileLineReader("ReadTranco", stats, FILES.TRANCO, n_lines=100_000)()

    _DEFAULT_ARGS = (
        "--alexa",
        "alookup",
        "--ipv4-lookup",
        "--ipv6-lookup",
    )

    for name, extra_args in {
        "normal": [],
        "normal_t30": ["--timeout", "30"],
        "normal_t60": ["--timeout", "60"],
        "iterative": ["--iterative"],
        "iterative_it10": ["--iterative", "--iteration-timeout", "10"],
        "iterative_it20": ["--iterative", "--iteration-timeout", "20"],
        "iterative_t30": ["--iterative", "--timeout", "30"],
        "iterative_t30_it10": ["--iterative", "--timeout", "30", "--iteration-timeout", "10"],
        "iterative_t30_it20": ["--iterative", "--timeout", "30", "--iteration-timeout", "20"],
        "iterative_t60": ["--iterative", "--timeout", "60"],
        "iterative_t60_it10": ["--iterative", "--timeout", "60", "--iteration-timeout", "10"],
        "iterative_t60_it20": ["--iterative", "--timeout", "60", "--iteration-timeout", "20"],
    }.items():
        try:
            ZDNS(
                stats, EXEUTABLES.ZDNS, *_DEFAULT_ARGS, *extra_args, cache_as_format=FileFormat.TXT, name_overwrite=name
            )(input_string_list=tranco, cache_file=f"out_test/{name}.json")
        except subprocess.CalledProcessError as e:
            print(f"Failed for {name}")
            raise e


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)-26s %(message)s")
    # main(10, False)
    # main(None, True)
    main()
    # test_zdns()
