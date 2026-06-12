#!/usr/bin/env python3

import subprocess
import sys
import re
import math

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

def parse_mean_latency_from_benchmark_stdout(stdout):
    token_re = re.compile(r"([0-9]+(?:\.[0-9]+)?)\s*(ns|us|ms|s)")
    for line in stdout.splitlines():
        tokens = token_re.findall(line)
        if len(tokens) == 3:
            mean_value, mean_unit = tokens[0]
            return float(mean_value), mean_unit

    raise ValueError("Unable to parse mean latency from benchmark output")

def compile_benchmarks(clean=False):
    if clean:
        try:
            result = subprocess.run(["./build-bench.sh", "--clean"], check=True, capture_output=True, text=True)
            print("Benchmarks cleaned successfully")
        except subprocess.CalledProcessError as e:
            print(f"Error: Benchmark clean failed\n{e.stderr}")
            sys.exit(1)
    else:
        try:
            result = subprocess.run(["./build-bench.sh"], check=True, capture_output=True, text=True)
            print("Benchmarks compiled successfully")
        except subprocess.CalledProcessError as e:
            print(f"Error: Benchmark compilation failed\n{e.stderr}")
            sys.exit(1)

def get_iblt_ss_computation_rt_benchmark_result(log2_db_size, db_entry_bitlen, max_match_count, num_iblt_copies):
    try:
        result = subprocess.run(["./build/ss_iblt_bench", "--benchmark-samples", "10", f"[db_size=2^{log2_db_size}][db_entry_bitlen={db_entry_bitlen}][resp_max_match_count={max_match_count}][num_ss_iblt_copies={num_iblt_copies}]"], check=True, capture_output=True, text=True)
        return parse_mean_latency_from_benchmark_stdout(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error: SS IBLT computation benchmark execution failed\n{e.stderr}")
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

def get_iblt_ss_decoding_rt_benchmark_result(db_entry_bitlen, max_match_count, num_iblt_copies):
    try:
        result = subprocess.run(["./build/ss_iblt_bench", "--benchmark-samples", "10", f"[db_entry_bitlen={db_entry_bitlen}][resp_max_match_count={max_match_count}][num_ss_iblt_copies={num_iblt_copies}][decoding]"], check=True, capture_output=True, text=True)
        return parse_mean_latency_from_benchmark_stdout(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error: SS IBLT reconstruction benchmark execution failed\n{e.stderr}")
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

def get_dpf_gen_benchmark_result(db_entry_bitlen):
    try:
        result = subprocess.run(["./build/dpf_bench","--benchmark-samples","10", f"[gen][n={db_entry_bitlen}]"], check=True, capture_output=True, text=True)
        return parse_mean_latency_from_benchmark_stdout(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error: DPF Key Generation benchmark execution failed\n{e.stderr}")
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

def get_dpf_eval_benchmark_result(db_entry_bitlen):
    try:
        result = subprocess.run(["./build/dpf_bench","--benchmark-samples","10", f"[eval][n={db_entry_bitlen}]"], check=True, capture_output=True, text=True)
        return parse_mean_latency_from_benchmark_stdout(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error: DPF Key Evaluation benchmark execution failed\n{e.stderr}")
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

def get_sk_hd_gen_benchmark_result(db_entry_bitlen):
    try:
        result = subprocess.run(["./build/sk_hd_fss_bench","--benchmark-samples","10", f"[sk_hd_fss][gen][n={db_entry_bitlen}]"], check=True, capture_output=True, text=True)
        return parse_mean_latency_from_benchmark_stdout(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error: SK HD FSS Key Generation benchmark execution failed\n{e.stderr}")
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

def get_sk_hd_eval_benchmark_result(db_entry_bitlen):
    try:
        result = subprocess.run(["./build/sk_hd_fss_bench","--benchmark-samples","10", f"[sk_hd_fss][eval][n={db_entry_bitlen}]"], check=True, capture_output=True, text=True)
        return parse_mean_latency_from_benchmark_stdout(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error: SK HD FSS Key Evaluation benchmark execution failed\n{e.stderr}")
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

def get_pk_hd_gen_benchmark_result(db_entry_bitlen):
    try:
        result = subprocess.run(["./build/pk_hd_fss_bench","--benchmark-samples","10", f"[pk_hd_fss][key_gen][n={db_entry_bitlen}][hd_threshold=1]"], check=True, capture_output=True, text=True)
        return parse_mean_latency_from_benchmark_stdout(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error: PK HD FSS Key Generation benchmark execution failed\n{e.stderr}")
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

def get_pk_hd_eval_benchmark_result(db_entry_bitlen):
    try:
        result = subprocess.run(["./build/pk_hd_fss_bench","--benchmark-samples","10", f"[pk_hd_fss][eval][n={db_entry_bitlen}][hd_threshold=1]"], check=True, capture_output=True, text=True)
        return parse_mean_latency_from_benchmark_stdout(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error: PK HD FSS Key Evaluation benchmark execution failed\n{e.stderr}")
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

def convert_time_to_seconds(value, unit):
    unit_multipliers = {
        'ns': 1e-9,
        'us': 1e-6,
        'ms': 1e-3,
        's': 1.0
    }
    if unit in unit_multipliers:
        return value * unit_multipliers[unit]
    else:
        raise ValueError(f"Unknown time unit: {unit}")

def est_fpir_sk_hd_query_rt(db_entry_bitlen):
    rt, time_unit = get_sk_hd_gen_benchmark_result(db_entry_bitlen)
    return convert_time_to_seconds(rt, time_unit)

def naive_hd_fss_num_dpfs(n, delta):
    """Return the number of DPFs needed for a naive HD-FSS construction with parameters n and delta."""
    return sum(n_choose_k(n, i) for i in range(delta + 1))

def est_naive_hd_fss_key_gen_rt(db_entry_bitlen, hd_threshold):
    single_dpf_gen_rt, time_unit = get_dpf_gen_benchmark_result(db_entry_bitlen)
    return convert_time_to_seconds(single_dpf_gen_rt, time_unit) * naive_hd_fss_num_dpfs(db_entry_bitlen, hd_threshold)

def est_naive_hd_fss_eval_rt(db_entry_bitlen, hd_threshold):
    single_dpf_eval_rt, time_unit = get_dpf_eval_benchmark_result(db_entry_bitlen)
    return convert_time_to_seconds(single_dpf_eval_rt, time_unit) * naive_hd_fss_num_dpfs(db_entry_bitlen, hd_threshold)

def est_naive_hd_fss_query_rt(db_entry_bitlen, hd_threshold):
    return est_naive_hd_fss_key_gen_rt(db_entry_bitlen, hd_threshold)

def est_naive_hd_fss_answer_rt(log2_db_size, db_entry_bitlen, hd_threshold, max_match_count, num_iblt_copies):
    single_naive_hd_fss_eval_rt_sec = est_naive_hd_fss_eval_rt(db_entry_bitlen, hd_threshold)
    total_naive_hd_fss_eval_rt_sec = single_naive_hd_fss_eval_rt_sec * (2 ** log2_db_size)

    iblt_ss_computation_rt_sec = convert_time_to_seconds(*get_iblt_ss_computation_rt_benchmark_result(log2_db_size, db_entry_bitlen, max_match_count, num_iblt_copies))
    return total_naive_hd_fss_eval_rt_sec + iblt_ss_computation_rt_sec

def est_naive_hd_fss_reconstruct_rt(db_entry_bitlen, max_match_count, num_iblt_copies):
    iblt_ss_decoding_rt_sec = convert_time_to_seconds(*get_iblt_ss_decoding_rt_benchmark_result(db_entry_bitlen, max_match_count, num_iblt_copies))
    return iblt_ss_decoding_rt_sec

def est_fpir_sk_hd_answer_rt(log2_db_size, db_entry_bitlen, max_match_count, num_iblt_copies):
    
    log2_db_size = int(log2_db_size)
    db_entry_bitlen = int(db_entry_bitlen)
    max_match_count = int(max_match_count)
    num_iblt_copies = int(num_iblt_copies)

    if log2_db_size not in [10, 12, 14]: raise ValueError("log2_db_size must be either 10, 12, or 14")
    if db_entry_bitlen not in [16, 32, 64, 128]: raise ValueError("db_entry_bitlen must be one of 16, 32, 64, or 128")
    if max_match_count not in [64, 128]: raise ValueError("max_match_count must be either 64 or 128")
    if num_iblt_copies not in [2]: raise ValueError("num_iblt_copies must be one of [2]")

    print(f"Running benchmarks for log2_db_size={log2_db_size}, db_entry_bitlen={db_entry_bitlen}, max_match_count={max_match_count}, num_iblt_copies={num_iblt_copies}...")

    single_fss_key_eval_rt, single_fss_key_eval_rt_time_unit = get_sk_hd_eval_benchmark_result(db_entry_bitlen)
    iblt_ss_computation_rt, iblt_ss_computation_rt_time_unit = get_iblt_ss_computation_rt_benchmark_result(log2_db_size, db_entry_bitlen, max_match_count, num_iblt_copies)
    
    print("Benchmark successfully completed.")

    single_fss_key_eval_rt_sec = convert_time_to_seconds(single_fss_key_eval_rt, single_fss_key_eval_rt_time_unit)
    total_fss_eval_rt_sec = single_fss_key_eval_rt_sec * (2 ** log2_db_size)

    iblt_ss_computation_rt_sec = convert_time_to_seconds(iblt_ss_computation_rt, iblt_ss_computation_rt_time_unit)

    return total_fss_eval_rt_sec + iblt_ss_computation_rt_sec

def est_fpir_sk_hd_reconstruct_rt(db_entry_bitlen, max_match_count, num_iblt_copies):
    db_entry_bitlen = int(db_entry_bitlen)
    max_match_count = int(max_match_count)
    num_iblt_copies = int(num_iblt_copies)

    if db_entry_bitlen not in [16, 32, 64, 128]: raise ValueError("db_entry_bitlen must be one of 16, 32, 64, or 128")
    if max_match_count not in [64, 128]: raise ValueError("max_match_count must be either 64 or 128")
    if num_iblt_copies not in [2]: raise ValueError("num_iblt_copies must be one of [2]")

    print(f"Running benchmarks for db_entry_bitlen={db_entry_bitlen}, max_match_count={max_match_count}, num_iblt_copies={num_iblt_copies}...")

    iblt_ss_decoding_rt, time_unit = get_iblt_ss_decoding_rt_benchmark_result(db_entry_bitlen, max_match_count, num_iblt_copies)

    print("Benchmark successfully completed.")

    return convert_time_to_seconds(iblt_ss_decoding_rt, time_unit)

def est_fpir_pk_hd_query_rt(db_entry_bitlen):
    rt, time_unit = get_pk_hd_gen_benchmark_result(db_entry_bitlen)
    return convert_time_to_seconds(rt, time_unit)

def est_fpir_pk_hd_answer_rt(log2_db_size, db_entry_bitlen, max_match_count, num_iblt_copies):
    log2_db_size = int(log2_db_size)
    db_entry_bitlen = int(db_entry_bitlen)
    max_match_count = int(max_match_count)
    num_iblt_copies = int(num_iblt_copies)

    if log2_db_size not in [10, 12, 14]: raise ValueError("log2_db_size must be either 10, 12, or 14")
    if db_entry_bitlen not in [16, 32, 64, 128]: raise ValueError("db_entry_bitlen must be one of 16, 32, 64, or 128")
    if max_match_count not in [64, 128]: raise ValueError("max_match_count must be either 64 or 128")
    if num_iblt_copies not in [2]: raise ValueError("num_iblt_copies must be one of [2]")

    print(f"Running benchmarks for log2_db_size={log2_db_size}, db_entry_bitlen={db_entry_bitlen}, max_match_count={max_match_count}, num_iblt_copies={num_iblt_copies}...")

    single_fss_key_eval_rt, single_fss_key_eval_rt_time_unit = get_pk_hd_eval_benchmark_result(db_entry_bitlen)
    iblt_ss_computation_rt, iblt_ss_computation_rt_time_unit = get_iblt_ss_computation_rt_benchmark_result(log2_db_size, db_entry_bitlen, max_match_count, num_iblt_copies)
    
    print("Benchmark successfully completed.")

    single_fss_key_eval_rt_sec = convert_time_to_seconds(single_fss_key_eval_rt, single_fss_key_eval_rt_time_unit)
    total_fss_eval_rt_sec = single_fss_key_eval_rt_sec * (2 ** log2_db_size)

    iblt_ss_computation_rt_sec = convert_time_to_seconds(iblt_ss_computation_rt, iblt_ss_computation_rt_time_unit)

    return total_fss_eval_rt_sec + iblt_ss_computation_rt_sec

def est_fpir_pk_hd_reconstruct_rt(db_entry_bitlen, max_match_count, num_iblt_copies):
    db_entry_bitlen = int(db_entry_bitlen)
    max_match_count = int(max_match_count)
    num_iblt_copies = int(num_iblt_copies)

    if db_entry_bitlen not in [16, 32, 64, 128]: raise ValueError("db_entry_bitlen must be one of 16, 32, 64, or 128")
    if max_match_count not in [64, 128]: raise ValueError("max_match_count must be either 64 or 128")
    if num_iblt_copies not in [2]: raise ValueError("num_iblt_copies must be one of [2]")

    print(f"Running benchmarks for db_entry_bitlen={db_entry_bitlen}, max_match_count={max_match_count}, num_iblt_copies={num_iblt_copies}...")

    iblt_ss_decoding_rt, time_unit = get_iblt_ss_decoding_rt_benchmark_result(db_entry_bitlen, max_match_count, num_iblt_copies)

    print("Benchmark successfully completed.")

    return convert_time_to_seconds(iblt_ss_decoding_rt, time_unit)

def assert_log2_db_size_valid(log2_db_size):
    if log2_db_size not in [10, 12, 14]:
        raise ValueError("log2_db_size must be either 10, 12, or 14")

def assert_db_entry_bitlen_valid(db_entry_bitlen):
    if db_entry_bitlen not in [16, 32, 64, 128]:
        raise ValueError("db_entry_bitlen must be one of 16, 32, 64, or 128")

def assert_max_match_count_valid(max_match_count):
    if max_match_count not in [64, 128]:
        raise ValueError("max_match_count must be either 64 or 128")

def assert_num_iblt_copies_valid(num_iblt_copies):
    if num_iblt_copies not in [2]:
        raise ValueError("num_iblt_copies must be one of [2]")

def assert_fss_scheme_name_valid(fss_scheme_name):
    if fss_scheme_name not in ["sk_hd_fss", "pk_hd_fss", "naive_hd_fss"]:
        raise ValueError("fss_scheme_name must be one of 'sk_hd_fss', 'pk_hd_fss', or 'naive_hd_fss'")

def assert_fpir_algo_name_valid(fpir_algo_name):
    if fpir_algo_name not in ["query", "answer", "reconstruct"]:
        raise ValueError("fpir_algo_name must be one of 'query', 'answer', or 'reconstruct'")

def main():
    if len(sys.argv) != 8:
        print("Usage: est_fpir_perf.py <fss_scheme_name> <fpir_algo_name> <log2_db_size> <db_entry_bitlen> <distance_threshold> <max_match_count> <num_iblt_copies>")
        print("Example: est_fpir_perf.py sk_hd_fss answer 14 16 1 64 2")
        sys.exit(1)
    
    fss_scheme_name = sys.argv[1]
    fpir_algo_name = sys.argv[2]
    log2_db_size = int(sys.argv[3])
    db_entry_bitlen = int(sys.argv[4])
    distance_threshold = int(sys.argv[5])
    max_match_count = int(sys.argv[6])
    num_iblt_copies = int(sys.argv[7])

    assert_log2_db_size_valid(log2_db_size)
    assert_db_entry_bitlen_valid(db_entry_bitlen)
    assert_max_match_count_valid(max_match_count)
    assert_num_iblt_copies_valid(num_iblt_copies)
    assert_fss_scheme_name_valid(fss_scheme_name)
    assert_fpir_algo_name_valid(fpir_algo_name)

    print("Compiling benchmarks...")

    compile_benchmarks()
    
    if fss_scheme_name == "sk_hd_fss" and fpir_algo_name == "query":
        est_time_in_secs = est_fpir_sk_hd_query_rt(db_entry_bitlen)
        print(f"Estimated FPIR query time: {est_time_in_secs:.6f} seconds")
    elif fss_scheme_name == "sk_hd_fss" and fpir_algo_name == "answer":
        est_time_in_secs = est_fpir_sk_hd_answer_rt(log2_db_size, db_entry_bitlen, max_match_count, num_iblt_copies)
        print(f"Estimated FPIR answer time: {est_time_in_secs:.6f} seconds")
    elif fss_scheme_name == "sk_hd_fss" and fpir_algo_name == "reconstruct":
        est_time_in_secs = est_fpir_sk_hd_reconstruct_rt(db_entry_bitlen, max_match_count, num_iblt_copies)
        print(f"Estimated FPIR reconstruction time: {est_time_in_secs:.6f} seconds")
    elif fss_scheme_name == "pk_hd_fss" and fpir_algo_name == "query":
        est_time_in_secs = est_fpir_pk_hd_query_rt(db_entry_bitlen)
        print(f"Estimated FPIR query time: {est_time_in_secs:.6f} seconds")
    elif fss_scheme_name == "pk_hd_fss" and fpir_algo_name == "answer":
        est_time_in_secs = est_fpir_pk_hd_answer_rt(log2_db_size, db_entry_bitlen, max_match_count, num_iblt_copies)
        print(f"Estimated FPIR answer time: {est_time_in_secs:.6f} seconds")
    elif fss_scheme_name == "pk_hd_fss" and fpir_algo_name == "reconstruct":
        est_time_in_secs = est_fpir_pk_hd_reconstruct_rt(db_entry_bitlen, max_match_count, num_iblt_copies)
        print(f"Estimated FPIR reconstruction time: {est_time_in_secs:.6f} seconds")
    elif fss_scheme_name == "naive_hd_fss" and fpir_algo_name == "query":
        est_time_in_secs = est_naive_hd_fss_query_rt(db_entry_bitlen, distance_threshold)
        print(f"Estimated FPIR query time: {est_time_in_secs:.6f} seconds")
    elif fss_scheme_name == "naive_hd_fss" and fpir_algo_name == "answer":
        est_time_in_secs = est_naive_hd_fss_answer_rt(log2_db_size, db_entry_bitlen, distance_threshold, max_match_count, num_iblt_copies)
        print(f"Estimated FPIR answer time: {est_time_in_secs:.6f} seconds")
    elif fss_scheme_name == "naive_hd_fss" and fpir_algo_name == "reconstruct":
        est_time_in_secs = est_naive_hd_fss_reconstruct_rt(db_entry_bitlen, max_match_count, num_iblt_copies)
        print(f"Estimated FPIR reconstruction time: {est_time_in_secs:.6f} seconds")
    else:
        print(f"Error: Unsupported combination of fss_scheme_name '{fss_scheme_name}' and fpir_algo_name '{fpir_algo_name}'")
        sys.exit(1)

if __name__ == "__main__":
    main()
