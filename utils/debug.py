import os
import linecache
from queue import Queue, Empty
import types
import tracemalloc
import threading


class MemoryMonitor(threading.Thread):
    def __init__(self, poll_interval=60, key_type="lineno", limit=5, trace_depth=...) -> None:
        super().__init__(name="MemoryMonitor", daemon=True)
        self.poll_interval = poll_interval
        self.queue = Queue()
        self.key_type = key_type
        self.limit = limit
        self.trace_depth = trace_depth

        self.last_stats = None

    def stop(self):
        self.queue.put(None)

    def diff_prefix(self, num, negative=True):
        if num >= 0:
            return "+"
        elif negative:
            return "-"
        else:
            return ""

    def format_bytes(self, num, diff=False):
        for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi", "Yi"]:
            if abs(num) < 1024.0 or unit == "Yi":
                break
            num /= 1024.0
        prefix = ""
        if diff:
            prefix = self.diff_prefix(num)
            num = abs(num)
        return prefix + f"{num:.1f} {unit:2s}B".rjust(9)

    def format_lineno(self, stat):
        frame = stat.traceback[0]
        # replace "/path/to/module/file.py" with "module/file.py"
        filename = os.sep.join(frame.filename.split(os.sep)[-2:])

        return (
            True,
            f"{filename}:{frame.lineno}",
            f"{linecache.getline(frame.filename, frame.lineno).strip()}",
        )

    def format_traceback(self, stat):
        for frame in stat.traceback[::-1]:
            # replace "/path/to/module/file.py" with "module/file.py"
            filename = os.sep.join(frame.filename.split(os.sep)[-2:])
            yield f"{filename}:{frame.lineno}"
            yield f"\t{linecache.getline(frame.filename, frame.lineno).strip()}"

    def print_stat(self, top_stats):
        print(f"Top {self.limit} {self.key_type}")
        for index, stat in enumerate(top_stats[: self.limit], 1):
            additional_info = ""
            if self.key_type == "lineno":
                additional_info = self.format_lineno(stat)
            elif self.key_type == "traceback":
                additional_info = self.format_traceback(stat)
            else:
                additional_info = f"--error no printer for key_type {self.key_type}--"

            first_line_info = ""
            further_lines = ()
            if isinstance(additional_info, types.GeneratorType):
                additional_info = tuple(additional_info)

            if isinstance(additional_info, tuple):
                if additional_info[0] is True:
                    first_line_info = additional_info[1]
                    further_lines = ("\t" + x for x in additional_info[2:])
                else:
                    further_lines = ("\t" + x for x in additional_info)
            else:
                assert isinstance(additional_info, str)
                if "\n" not in additional_info:
                    first_line_info = additional_info
                else:
                    first_line_info, *further_lines = additional_info.split("\n")

            print(f"#{index:2d}: ", end="")
            print(f"{self.format_bytes(stat.size)}", end="")
            if isinstance(stat, tracemalloc.StatisticDiff):
                print(f" ({self.format_bytes(stat.size_diff, True)})", end="")
            print(f" | {stat.count:7d} occurences", end="")
            if isinstance(stat, tracemalloc.StatisticDiff):
                print(f" ({self.diff_prefix(stat.count_diff, False)}{stat.count_diff})", end="")
            if first_line_info:
                print(f" | {first_line_info}", end="")
            print()

            if further_lines:
                print(*further_lines, sep="\n")

        other = top_stats[self.limit :]
        if other:
            size = sum(stat.size for stat in other)
            print(f"{len(other)} other: {self.format_bytes(size)}")

        total = sum(stat.size for stat in top_stats)
        print(f"Total allocated size: {self.format_bytes(total)}")

    def snapshot(self):
        print("Taking Memory Snapshot")
        snapshot = tracemalloc.take_snapshot()
        # print("Filtering Memory Snapshot")
        # snapshot = snapshot.filter_traces(
        #     (
        #         tracemalloc.Filter(False, "<frozen importlib._bootstrap>"),
        #         tracemalloc.Filter(False, "<unknown>"),
        #     )
        # )
        print("Calculating Memory Statistics")
        if self.last_stats:
            top_stats = snapshot.compare_to(self.last_stats, self.key_type)
            print("Sorted by biggest change")
            self.print_stat(top_stats)
            top_stats.sort(reverse=True, key=tracemalloc.Statistic._sort_key)
        else:
            top_stats = snapshot.statistics(self.key_type)
        print("Sorted by most allocated")
        self.print_stat(top_stats)

        self.last_stats = snapshot

    def run(self):
        if self.trace_depth is ...:
            trace_depth = 1
            if self.key_type == "traceback":
                trace_depth = 4
        else:
            trace_depth = self.trace_depth
        tracemalloc.start(trace_depth)
        while True:
            try:
                self.queue.get(timeout=self.poll_interval)
            except Empty:
                self.snapshot()
            else:
                break
        tracemalloc.stop()
