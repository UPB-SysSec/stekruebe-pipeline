# A hopefully more configurable way to run our whole pipeline
import csv
import ipaddress
import logging
import multiprocessing
import os
import os.path as op
import subprocess
import shutil
import sys
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable, Mapping
from enum import Enum
from itertools import chain
from random import shuffle
from typing import Any, Generic, TypeVar

from utils import JsonFilter
from utils import json_serialization as json
from urllib.parse import urlparse



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
        # track highest run id for each stage statistic
        self.seen = dict()

    def store(self, stage_name: str, name: str, data: Any, RUN_ID: int = 0):
        if (stage_name, name) in self.seen:
            RUN_ID = self.seen[(stage_name, name)] + 1
        with open(self.filename, "a", newline="") as f:
            csv.writer(f).writerow([stage_name, name, json.dumps(data), RUN_ID])
        self.seen.update({(stage_name, name): RUN_ID})


class Stage(ABC, Generic[OUTPUTS]):
    def __init__(self, name, stats: _Stats) -> None:
        # self.logger = logging.getLogger(__name__ + "." + name) # i dont like the __name__ look
        self.logger = logging.getLogger(name)
        self.name = name
        self.stats = stats

    def _store_stat(self, name: str, data: Any):
        if self.stats:
            self.stats.store(self.name, name, data)

    @abstractmethod
    def run_stage(self, *args, **kwargs) -> OUTPUTS: ...

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

    def __call__(
        self,
        *args,
        cache_file,
        cache_write=True,
        cache_load=True,
        dry_run=False,
        **kwargs,
    ):
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

        # sometimes name servers apparently return wacky stuff and we don't want ZDNS to error out
        filtered_input_string_list = [ln for ln in input_string_list if "," not in ln and " " not in ln]
        self.logger.warning(f"Filtered out {len(filtered_input_string_list) - len(input_string_list)} non-URLs")


        ret = super().run_stage(filtered_input_string_list)
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


class ZMAP4(SimpleSubprocessStage):
    def __init__(self, stats, *args, name_overwrite="ZMAP4", **kwargs) -> None:
        super().__init__(name_overwrite, stats, *args, **kwargs)

    def run_stage(self, blocklist=None, allowlist=None) -> list[str]:
        # dynamically overwrite blocklist and allowlist by changing args following -b and -w respectively

        # FIXME: This is dirty but should be good enough for now (LAST WORDS OF A LAZY PROGRAMMER)
        new_args = list(self.args)
        if blocklist:
            if "-b" not in new_args:
                new_args.append("-b")
            new_args[new_args.index("-b") + 1] = str(blocklist)
        if allowlist:
            if "-w" not in new_args:
                new_args.append("-w")
            new_args[new_args.index("-w") + 1] = str(allowlist)
        self.args = new_args
        # zmap fails loudly if allow list is empty, so we need to check for that
        if "-w" in self.args:
            allowlist = self.args[self.args.index("-w") + 1]
            # if file has any lines we proceed
            with open(allowlist) as f:
                if len(f.readlines()) == 0:
                    self.logger.warning(f"Allowlist {allowlist} is empty. Skipping.")
                    return []

        print(f"Zmap4 invoked with {self.args}")
        start = time.time()
        ret = super().run_stage()
        end = time.time()
        self._store_stat("zmap4 runtime", end - start)
        return ret


class ZMAP6(SimpleSubprocessStage):
    def __init__(self, stats, *args, name_overwrite="ZMAP6", **kwargs) -> None:
        super().__init__(name_overwrite, stats, *args, **kwargs)

    def run_stage(self, targets=None) -> list[str]:
        # dynamically overwrite targets by changing args following --ipv6-target-file
        # FIXME: This is dirty but should be good enough for now (LAST WORDS OF A LAZY PROGRAMMER)
        new_args = list(self.args)
        if targets:
            if "--ipv6-target-file" not in new_args:
                new_args.append("--ipv6-target-file")
            new_args[new_args.index("--ipv6-target-file") + 1] = str(targets)
        self.args = new_args

        start = time.time()
        ret = super().run_stage()
        end = time.time()
        self._store_stat("zmap6 runtime", end - start)
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


class DomainFromAlexaFormat(Stage[list[str]]):
    def __init__(self, stats: _Stats) -> None:
        super().__init__("DomainFromAlexaFormat", stats)

    def _run_stage(self, alexa_format: list[str]) -> Iterable[str]:
        for line in alexa_format:
            yield line.split(",", 1)[1]

    def run_stage(self, alexa_format: list[str]) -> list[str]:
        return list(self._run_stage(alexa_format))


class DuplicateDomainFilter(Stage[list[str]]):
    def __init__(self, stats: _Stats) -> None:
        super().__init__("DuplicateDomainFilter", stats)
        self.seen = set()

    def _run_stage(self, domains: list[str]) -> Iterable[str]:
        # keeps a set of all domains that have been seen across multiple calls to run_stage and yields only the new domains
        for domain in domains:
            if domain not in self.seen:
                self.seen.add(domain)
                yield domain

    def run_stage(self, domains: list[str]) -> list[str]:
        # keeps a set of all domains that have been seen across multiple calls to run_stage and only returns only the list of new domains
        return list(self._run_stage(domains))


class MapIPsToDomains(CacheableStage[list[tuple[str, str]]]):
    def __init__(self, stats: _Stats) -> None:
        super().__init__("MapIPsToDomains", stats)

    def _run_stage(self, resolved_domains: list, ips: list[str]):
        ips_to_domains = {}
        for line in resolved_domains:
            item = json.loads(line)
            domanin = item.get("name")
            item_data = item.get("data", {})
            if item_data is None:
                item_data = {}
            for ip in chain(
                item_data.get("ipv4_addresses", []),
                item_data.get("ipv6_addresses", []),
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
        # output_file: str,
        out_filter: JsonFilter,
        *args,
        processing_procs=8,
    ) -> None:
        super().__init__(name, stats)
        self.executable = executable
        self.args = args
        self.processing_procs = processing_procs

        self.connections_per_host = 1
        self.out_filter = out_filter
        # self.output_file = output_file
        for arg in self.args:
            if arg.startswith("--connections-per-host="):
                self.connections_per_host = int(arg.split("=")[1])

    def _send_targets(self, proc: subprocess.Popen, ip_and_hosts: list[tuple[str, str]]):
        for ip, host in ip_and_hosts:
            ln = f"{ip},{host}\n"
            if not proc.text_mode:
                ln = ln.encode()
            proc.stdin.write(ln)
        proc.stdin.flush()
        proc.stdin.close()
        self.logger.info(f"Sent {len(ip_and_hosts)} targets to zgrab")

    def run_stage(self, output_file: str, ip_and_hosts: list[tuple[str, str]]) -> int:
        self.output_file = output_file  # TODO: temporary
        if op.isfile(self.output_file):
            self.logger.warning(f"Output file {self.output_file!r} already exists. Skipping.")
            return -1

        EXPECTED = len(ip_and_hosts) * self.connections_per_host
        last_ipercent = 0
        last_t = time.time()
        last_n = 0

        start = last_t
        processed_items = 0
        stderr = b""

        def _print_progress():
            nonlocal last_t, last_n, last_ipercent
            now = time.time()
            percent = 100 * processed_items / EXPECTED
            ipercent = int(percent)
            if now - last_t < 2 and last_ipercent >= ipercent:
                self.logger.debug(
                    f"Skipping progress update. Last update was {now - last_t:.2f}s ago at {last_ipercent}% (now {ipercent}%)"
                )
                # don't print too often
                return
            self.logger.info(
                f"Currently at {processed_items:7d}/{EXPECTED} ({percent:5.2f}%) | {processed_items/(now-start):5.2f} {(processed_items-last_n)/(now-last_t):5.2f} items/s"
            )
            last_ipercent = ipercent
            last_t = now
            last_n = processed_items

        print("Running:", self.executable, *self.args)
        with (
            open(self.output_file, "w") if self.output_file else open(os.devnull, "w") as fo,
            multiprocessing.Pool(self.processing_procs) as pool,
            # create the subprocess last, if the pool is opened afterwards the subprocess does not properly closed
            subprocess.Popen(
                [self.executable, *self.args],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                # bufsize=0,
            ) as proc,
        ):

            def _progress_thread():
                PRINT_EVERY = 5 * 60
                self.logger.debug(f"Starting progress monitoring thread. Printing every {PRINT_EVERY}s")
                while processed_items < EXPECTED and proc.poll() is None:
                    now = time.time()
                    time_since_last_print = now - last_t
                    if time_since_last_print > PRINT_EVERY:
                        _print_progress()
                        time.sleep(PRINT_EVERY)
                    else:
                        time.sleep(PRINT_EVERY - time_since_last_print)
                self.logger.info(
                    f"Finished processing {processed_items} (Expected {EXPECTED}) items; exitcode {proc.poll()}"
                )

            progress_thread = threading.Thread(target=_progress_thread, daemon=True)
            progress_thread.start()

            inputthread = threading.Thread(
                target=self._send_targets,
                args=(proc, ip_and_hosts),
                name="ZGRAB input thread",
                daemon=True,
            )
            inputthread.start()
            while (returncode := proc.poll()) is None:
                # line = proc.stdout.readline()
                # for processed_line in map(self.out_filter.apply_str_in_str_out, proc.stdout):
                for processed_line in pool.imap(self.out_filter, proc.stdout):
                    processed_items += 1
                    fo.write(processed_line)
                    fo.write("\n")
                    ipercent = int(100 * processed_items / EXPECTED)
                    if ipercent > last_ipercent:
                        _print_progress()
            self.logger.info(f"Finished processing {processed_items} items; exitcode {returncode}")
            stderr += proc.stderr.read()

        if returncode:
            raise subprocess.CalledProcessError(proc.returncode, self.args, proc.stdout, proc.stderr)
        self.logger.info(f"Zgrab Output: {stderr!r}")
        status_line = stderr.decode().strip().split("\n")[-1]
        status = json.loads(status_line)
        self._store_stat("zgrab_status", status)
        return processed_items / self.connections_per_host


class CertificateSANExtractor(Stage[list[str]]):
    def __init__(self, stats: _Stats) -> None:
        super().__init__("CertificateSANExtractor", stats)

    def parse_san_from_result(self, item):
        try:
            return item["result"]["response"]["request"]["tls_log"]["handshake_log"]["server_certificates"][
                "certificate"
            ]["parsed"]["extensions"]["subject_alt_name"]["dns_names"]
        except KeyError:
            return []

    def run_stage(self, zgrab_out_file: str) -> list[str]:
        all_sans = set()
        with open(zgrab_out_file) as f:
            while ln := f.readline():
                item = json.loads(ln)
                all_sans.update(self.parse_san_from_result(item["data"]["https-tls1_3"]))
                all_sans.update(self.parse_san_from_result(item["data"]["https-tls1_0-1_2"]))

        # TODO: the www thing is included twice in the diagram, is this enough?
        for san in all_sans.copy():
            if san.startswith("*."):
                base_domain = san[2:]
                all_sans.remove(san)
                if not base_domain.startswith("www."):
                    all_sans.add(f"www.{base_domain}")
                all_sans.add(base_domain)

        return list(all_sans)


class PostProcessZGrab(Stage[None]):
    def __init__(self, stats: _Stats, connections_per_host: int) -> None:
        super().__init__("Postprocess Zgrab", stats)
        self.connections_per_host = connections_per_host

    def parse_https_result(self, item):
        try:
            tls_log = item["response"]["request"]["tls_log"]
        except KeyError:
            return {"_error": "No tls_log"}
        else:
            return self.parse_tls_result(tls_log)

    def parse_tls_result(self, item):
        ret = {}
        try:
            server_hello = item["handshake_log"]["server_hello"]
            version = server_hello["version"]
            if "supported_versions" in server_hello:
                version = server_hello["supported_versions"]["selected_version"]
            version = version["name"]
            ret["version"] = version
        except KeyError:
            ret["_error"] = "No server hello -> no version"

        if version:
            try:
                if version == "TLSv1.3":
                    post_handshake = item["handshake_log"]["post_handshake"]
                    tickets = post_handshake["session_tickets"]
                    ret["tickets"] = []
                    for ticket in tickets:
                        ret["tickets"].append(ticket["value"])
                else:
                    ret["ticket"] = item["handshake_log"]["session_ticket"]["value"]
            except KeyError:
                ret["_error"] = f"No Tickets found"
        return ret

    def parse_result(self, item):
        protocol = item["protocol"]
        result = item.get("result", None)
        ret = {}
        ret["status"] = item.get("status", None)
        if "error" in item:
            ret["error"] = item["error"]

        if result:
            if protocol == "http":
                ret.update(self.parse_https_result(result))
            elif protocol == "tls":
                ret.update(self.parse_tls_result(result))
            else:
                raise ValueError(f"Unknown protocol {protocol}")
        else:
            ret["_error"] = "No result"
        return ret

    def run_stage(self, zgrab_out_file: str, outfile: str) -> None:
        if op.isfile(outfile):
            self.logger.warning(f"Output file {outfile!r} already exists. Skipping.")
            return -1

        with open(zgrab_out_file) as f_in, open(outfile, "w") as f_out:
            f_in.seek(0, os.SEEK_END)
            total = f_in.tell()
            f_in.seek(0)

            grouped_zgrab_results = {}
            handled = set()

            while ln := f_in.readline():
                item = json.loads(ln)
                ip = item["ip"]
                domain = item["domain"]

                zgrab_result = {}
                for probe, value in item["data"].items():
                    assert probe not in zgrab_result
                    zgrab_result[probe] = self.parse_result(value)

                key = (ip, domain)
                if key not in grouped_zgrab_results:
                    assert key not in handled
                    grouped_zgrab_results[key] = []

                grouped_zgrab_results[key].append(zgrab_result)

                if len(grouped_zgrab_results[key]) >= self.connections_per_host:
                    json.dump(
                        {
                            "ip": ip,
                            "domain": domain,
                            "results": grouped_zgrab_results[key],
                        },
                        f_out,
                    )
                    f_out.write("\n")
                    del grouped_zgrab_results[key]
                    handled.add(key)
                    if len(handled) % 10_000 == 0:
                        print(
                            f"Handled: {len(handled):7d} ({100*f_in.tell()/total:6.2f}%) | Currently open: {len(grouped_zgrab_results):7d}"
                        )
            assert not grouped_zgrab_results, grouped_zgrab_results
            return len(handled)


class CONST:
    IPv6SRC = "2001:638:502:ce18::6"
    ZGRAB_CONNECTIONS_PER_HOST = 5


class EXEUTABLES:
    JQ = "jq"
    CUT = "cut"
    ZDNS = "./zdns/zdns"
    ZMAP4 = "./zmap/src/zmap"
    ZMAP6 = "./zmapv6/src/zmap"
    ZGRAB = "./zgrab2_tls13/cmd/zgrab2/zgrab2"


if not op.isdir("out"):
    os.mkdir("out")


class FILES:
    TRANCO = "../tranco_G6KVK.csv"
    BLOCKLIST_4 = "blocklist.txt" # not needed for AE Version
    BLOCKLIST_6 = "blocklist.txt" # not needed for AE Version

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

    def get(item, RUN_ID=None):
        if RUN_ID is None:
            return getattr(FILES, item)
        return getattr(FILES, item).replace(".", f".r{RUN_ID:02d}.")


ZGRAB_FILTER = JsonFilter(
    "data.https-tls1_3.result.*",
    "!data.https-tls1_3.result.response.request.tls_log",
    "data.https-tls1_0-1_2.result.*",
    "!data.https-tls1_0-1_2.result.response.request.tls_log",
    # "*.handshake_log.server_certificates.*.parsed",
    "*.handshake_log.server_certificates.chain.parsed",
)


def main(TRANCO_NUM=None, DRY_RUN=False, RUN_ID=0):
    logger = logging.getLogger("Main")
    stats = _Stats("out/stats.csv")

    class STAGES:
        TRANCO = FileLineReader("ReadTranco", stats, FILES.TRANCO, n_lines=TRANCO_NUM)
        DOMAIN_FROM_ALEXA_FORMAT = DomainFromAlexaFormat(stats)
        ZDNS = ZDNS(
            stats,
            EXEUTABLES.ZDNS,
            # "--alexa", # not necessary with stage DOMAIN_FROM_ALEXA_FORMAT, for consistency with subsequent runs
            "alookup",
            "--ipv4-lookup",
            "--ipv6-lookup",
            "--name-servers=127.0.0.1:8053", # AE version
            cache_as_format=FileFormat.TXT,
        )
        DUPLICATE_DOMAINS = DuplicateDomainFilter(stats)
        JQ4 = SimpleSubprocessStage(
            "JQ4",
            stats,
            EXEUTABLES.JQ,
            "-r",
            ".data.ipv4_addresses | select(. != null) | .[]",
        )
        JQ6 = SimpleSubprocessStage(
            "JQ6",
            stats,
            EXEUTABLES.JQ,
            "-r",
            ".data.ipv6_addresses | select(. != null) | .[]",
        )
        BLOCKLIST4 = BlocklistFilter("Blocklist4", stats, FILES.get("BLOCKLIST_4"))
        BLOCKLIST6 = BlocklistFilter("Blocklist6", stats, FILES.get("BLOCKLIST_6"))
        ZMAP4 = ZMAP4(
            stats,
            EXEUTABLES.ZMAP4,
            "-b",
            str(FILES.get("BLOCKLIST_4")),
            "-w",
            str(FILES.get("FILTERED_4_IPLIST")),  # this changes on each run
        )
        ZMAP6 = ZMAP6(
            stats,
            EXEUTABLES.ZMAP6,
            "-M",
            "ipv6_tcp_synscan",
            "--ipv6-source-ip",
            CONST.IPv6SRC,
            "--ipv6-target-file",
            str(FILES.get("FILTERED_6_IPLIST")),  # this changes on each run
        )
        MERGE_UNIQ = MergeUniq(stats)
        MAP_IPS_TO_DOMAINS = MapIPsToDomains(stats)
        ZGRAB = ZgrabRunner(
            "Zgrab",
            stats,
            EXEUTABLES.ZGRAB,
            # FILES.ZGRAB_OUT, # this changes on each run
            ZGRAB_FILTER.apply_str_in_str_out,
            "multiple",
            "-c",
            "get-ticket-for-grouping.ini",
            f"--connections-per-host={CONST.ZGRAB_CONNECTIONS_PER_HOST}",
        )
        EXTRACT_NEW_SANS = CertificateSANExtractor(stats)
        PP_ZGRAB = PostProcessZGrab(stats, CONST.ZGRAB_CONNECTIONS_PER_HOST)

    # Initial domains loaded from tranco
    tranco_ranking = STAGES.TRANCO()
    domains = STAGES.DOMAIN_FROM_ALEXA_FORMAT(tranco_ranking)
    del tranco_ranking

    # do while new_sans is not empty
    while True:
        logger.info(f"Starting run {RUN_ID}")
        unique_domains = STAGES.DUPLICATE_DOMAINS(domains)
        # TODO store new domains in a file
        if not unique_domains:
            break
        with open(f"out/new_domains_{RUN_ID}.txt", "w") as f:
            f.write("\n".join(unique_domains))
        resolved_hosts = STAGES.ZDNS(
            input_string_list=unique_domains,
            cache_file=FILES.get("RESOLVED_DOMAINS", RUN_ID),
            dry_run=DRY_RUN,
        )

        IPv4s = STAGES.JQ4(resolved_hosts, cache_file=FILES.get("RESOLVED_IPS4", RUN_ID))
        IPv6s = STAGES.JQ6(resolved_hosts, cache_file=FILES.get("RESOLVED_IPS6", RUN_ID))

        IPv4s = STAGES.BLOCKLIST4(IPv4s, cache_file=FILES.get("FILTERED_4_IPLIST", RUN_ID))
        IPv6s = STAGES.BLOCKLIST6(IPv6s, cache_file=FILES.get("FILTERED_6_IPLIST", RUN_ID))

        # AE Version, our Docker containers will be reachable, and zmap does not love using the local docker bridge
        # IPv4s = STAGES.ZMAP4(
        #     allowlist=FILES.get("FILTERED_4_IPLIST", RUN_ID),
        #     cache_file=FILES.get("HTTPS_4_IPLIST", RUN_ID),
        #     dry_run=DRY_RUN,
        # )
        # IPv6s = STAGES.ZMAP6(
        #     targets=FILES.get("FILTERED_6_IPLIST", RUN_ID),
        #     cache_file=FILES.get("HTTPS_6_IPLIST", RUN_ID),
        #     dry_run=DRY_RUN,
        # )

        IPs = STAGES.MERGE_UNIQ(IPv4s, IPv6s, cache_file=FILES.get("MERGED_IP_LIST", RUN_ID))
        del IPv4s, IPv6s

        ip_and_hosts = STAGES.MAP_IPS_TO_DOMAINS(
            resolved_hosts,
            IPs,
            cache_file=FILES.get("MERGED_HOST_LIST", RUN_ID),
            dry_run=DRY_RUN,
        )
        del resolved_hosts
        if not DRY_RUN:
            STAGES.ZGRAB(ip_and_hosts=ip_and_hosts, output_file=FILES.get("ZGRAB_OUT", RUN_ID))

        new_sans = STAGES.EXTRACT_NEW_SANS(FILES.get("ZGRAB_OUT", RUN_ID))
        STAGES.PP_ZGRAB(FILES.get("ZGRAB_OUT", RUN_ID), FILES.get("ZGRAB_MERGED_OUT", RUN_ID))
        if not new_sans:
            break
        domains = new_sans
        RUN_ID += 1
    # STAGES.MERGE_RUNS(["out/6_zgrab*.json", "out/7_merged_zgrab*.json"]) # TODO: doing this cleanly is a bit more complicated


def test_zdns():
    if not op.isdir("out_test"):
        os.mkdir("out_test")
    stats = _Stats("out_test/stats.csv")

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
        "iterative_t30_it10": [
            "--iterative",
            "--timeout",
            "30",
            "--iteration-timeout",
            "10",
        ],
        "iterative_t30_it20": [
            "--iterative",
            "--timeout",
            "30",
            "--iteration-timeout",
            "20",
        ],
        "iterative_t60": ["--iterative", "--timeout", "60"],
        "iterative_t60_it10": [
            "--iterative",
            "--timeout",
            "60",
            "--iteration-timeout",
            "10",
        ],
        "iterative_t60_it20": [
            "--iterative",
            "--timeout",
            "60",
            "--iteration-timeout",
            "20",
        ],
    }.items():
        try:
            ZDNS(
                stats,
                EXEUTABLES.ZDNS,
                *_DEFAULT_ARGS,
                *extra_args,
                cache_as_format=FileFormat.TXT,
                name_overwrite=name,
            )(input_string_list=tranco, cache_file=f"out_test/{name}.json")
        except subprocess.CalledProcessError as e:
            print(f"Failed for {name}")
            raise e


def test_zgrab():
    ZGRAB = ZgrabRunner(
        "Zgrab",
        None,
        EXEUTABLES.ZGRAB,
        "/dev/null",
        ZGRAB_FILTER.apply_str_in_str_out,
        "multiple",
        "-c",
        "get-ticket-for-grouping.ini",
    )
    if False:
        ZGRAB = ZgrabRunner(
            "Zgrab",
            None,
            "/usr/bin/cat",
            "/dev/null",
            ZGRAB_FILTER,
            "out/large_zgrab_output.json",
        )
    if False:
        ZGRAB = ZgrabRunner(
            "Zgrab",
            None,
            "/data/cdn_ticket/zgrab2_dummy.py",
            "/dev/null",
            ZGRAB_FILTER,
            "out/large_zgrab_output.json",
        )
    # ZGRAB([("1.1.1.1", "foo.bar")])
    ZGRAB([("20.70.246.20", "microsoft.com")])


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)-7s | %(name)-25s.%(funcName)-15s: %(message)s",
        stream=sys.stdout,
    )

    if len(sys.argv) > 1:
        FILES.TRANCO = sys.argv[1]
    n_lines = None
    if len(sys.argv) > 2:
        n_lines = int(sys.argv[2])
    # main(10, False)
    # # main(None, None)

    # AE Version
    for executable in [EXEUTABLES.JQ, EXEUTABLES.CUT, EXEUTABLES.ZDNS, EXEUTABLES.ZMAP4, EXEUTABLES.ZMAP6, EXEUTABLES.ZGRAB]:
        if shutil.which(executable) or os.path.isfile(executable):
            logging.getLogger("Requirements").info(f"{executable} exists and is executable.")
            pass
        else:
            logging.getLogger("Requirements").fatal(f"{executable} does not exist or is not executable.")
            exit(1)

    main(n_lines)
    # test_zdns()
    # test_zgrab()
