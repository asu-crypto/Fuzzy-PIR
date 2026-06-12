#!/usr/bin/env python3

"""Run Catch2 benchmarks and extract mean runtimes.

This script focuses on the benchmark sections used by the DPF benchmarks:
- SK DPF key pairs generated with n=...
- SK DPF Eval with n=...

The main entry point is ``extract_mean_runtimes``.
"""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Dict, Iterable


SECTION_RE = re.compile(r"^---+\n(?P<title>SK DPF (?:key pairs generated|Eval) with n=\d+)\n---+\n", re.MULTILINE)
BENCHMARK_ROW_RE = re.compile(r"^\s*(?P<benchmark>n=\d+)\s+\d+\s+\d+\s+[0-9.]+\s+[numk]?s\s*$", re.MULTILINE)
MEAN_ROW_RE = re.compile(r"^\s+(?P<mean>[0-9.]+\s+[numk]?s)\s+[0-9.]+\s+[numk]?s\s+[0-9.]+\s+[numk]?s\s*$", re.MULTILINE)


@dataclass(frozen=True)
class BenchmarkMean:
    """A parsed Catch2 benchmark mean runtime."""

    title: str
    benchmark: str
    mean_runtime: str


def extract_mean_runtimes(output: str) -> Dict[str, Dict[int, str]]:
    """Extract mean runtimes from Catch2 output.

    Returns a dictionary with two keys:
    - ``key_generation``: mapping from integer ``n`` to the mean runtime string
    - ``eval``: mapping from integer ``n`` to the mean runtime string
    """

    results: Dict[str, Dict[int, str]] = {"key_generation": {}, "eval": {}}

    sections = list(SECTION_RE.finditer(output))
    for index, section in enumerate(sections):
        title = section.group("title")
        section_start = section.end()
        section_end = sections[index + 1].start() if index + 1 < len(sections) else len(output)
        section_text = output[section_start:section_end]

        benchmark_match = BENCHMARK_ROW_RE.search(section_text)
        if not benchmark_match:
            continue

        mean_match = MEAN_ROW_RE.search(section_text, benchmark_match.end())
        if not mean_match:
            continue

        benchmark = benchmark_match.group("benchmark")
        n_value = int(benchmark.split("=")[1])
        mean_runtime = mean_match.group("mean")

        if "key pairs generated" in title:
            results["key_generation"][n_value] = mean_runtime
        else:
            results["eval"][n_value] = mean_runtime

    return results


def _read_input(args: Iterable[str]) -> str:
    """Run the benchmark binary and return its stdout."""

    args = list(args)
    if len(args) > 1:
        raise SystemExit("usage: parse_catch2_bench.py [path-to-benchmark-binary]")

    command = args[0] if len(args) == 1 else "./build/dpf_bench"
    completed = subprocess.run(
        [command],
        check=True,
        text=True,
        capture_output=True,
    )
    return completed.stdout


def n_choose_k(n: int, k: int) -> int:
    """Return the binomial coefficient C(n, k)."""

    if k < 0 or n < 0:
        raise ValueError("n and k must be non-negative")
    if k > n:
        return 0

    k = min(k, n - k)
    result = 1
    for i in range(1, k + 1):
        result = result * (n - k + i) // i
    return result

def run_dpf_bench(bench_exec_path: str) -> str:
    completed = subprocess.run(
        [bench_exec_path],
        check=True,
        text=True,
        capture_output=True,
    )
    return completed.stdout

def naive_hd_fss_num_dpfs(n: int, delta: int) -> int:
    """Return the number of DPFs needed for a naive HD-FSS construction with parameters n and delta."""
    return sum(n_choose_k(n, i) for i in range(delta + 1))

def est_naive_hd_fss_runtime(benchmark_result: Dict[str, Dict[int, str]], delta: int) -> Dict[str, Dict[int, float]]:
    estimated_rt_dict: Dict[str, Dict[int, float]] = {"key_generation": {}, "eval": {}}

    for benchmark_type in ("key_generation", "eval"):
        for n in (8, 16, 32, 64, 128):

            if n not in benchmark_result[benchmark_type]:
                raise ValueError(f"n={n} not found in benchmark results for {benchmark_type}")

            mean_runtime_str = benchmark_result[benchmark_type][n]
            mean_runtime_value, mean_runtime_unit = mean_runtime_str.split()
            mean_runtime_value = float(mean_runtime_value)

            if mean_runtime_unit == "s":
                estimated_rt_dict[benchmark_type][n] = mean_runtime_value * 1_000_000
            elif mean_runtime_unit == "ms":
                estimated_rt_dict[benchmark_type][n] = mean_runtime_value * 1_000
            elif mean_runtime_unit == "us":
                estimated_rt_dict[benchmark_type][n] = mean_runtime_value
            elif mean_runtime_unit == "ns":
                estimated_rt_dict[benchmark_type][n] = mean_runtime_value / 1_000
            else:
                raise ValueError(f"Unknown time unit: {mean_runtime_unit}")

            estimated_rt_dict[benchmark_type][n] *= naive_hd_fss_num_dpfs(n, delta)  

    return estimated_rt_dict



def main() -> None:
    output = run_dpf_bench("./build/dpf_bench")
    results = extract_mean_runtimes(output)

    print(results)

    for delta in (1, 2, 4, 8):
        print(f"\nEstimated naive HD-FSS runtimes for delta={delta}:")

        est_naive_hd_fss_runtime_dict = est_naive_hd_fss_runtime(results, delta)
        print("Estimated naive HD-FSS runtimes (us, ms, s):")
        for benchmark_type in ("key_generation", "eval"):
            print(f"\n{benchmark_type}:")
            for n in sorted(est_naive_hd_fss_runtime_dict[benchmark_type].keys()):
                est_rt_us = est_naive_hd_fss_runtime_dict[benchmark_type][n]
                est_rt_ms = est_rt_us / 1_000.0
                est_rt_s = est_rt_us / 1_000_000.0
                print(f"  n={n}: {est_rt_us:.2f} us | {est_rt_ms:.4f} ms | {est_rt_s:.6f} s")


if __name__ == "__main__":
    main()