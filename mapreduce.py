import os
import multiprocessing as mp
from collections import defaultdict
import re

def parse_log_line(line):
    pattern = r'\[(\d+/\w+/\d+):(\d+):\d+:\d+ \+\d+\] ".*?" (\d{3})'
    match = re.search(pattern, line)
    if match:
        hour = int(match.group(2))
        status = match.group(3)
        return status, hour
    return None, None

def map_chunk(chunk_lines):
    status_counts = defaultdict(int)
    hour_counts = defaultdict(int)
    for line in chunk_lines:
        status, hour = parse_log_line(line)
        if status:
            status_counts[status] += 1
        if hour is not None:
            hour_counts[str(hour)] += 1
    return status_counts, hour_counts

def run_mapreduce(file_path, num_workers=None):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    if not lines:
        return {}, {}

    total_lines = len(lines)
    if num_workers is None:
        num_workers = min(mp.cpu_count(), max(1, total_lines // 1000))
    chunk_size = max(1, total_lines // num_workers)
    chunks = [lines[i:i+chunk_size] for i in range(0, total_lines, chunk_size)]

    with mp.Pool(processes=num_workers) as pool:
        results = pool.map(map_chunk, chunks)

    total_status = defaultdict(int)
    total_hours = defaultdict(int)
    for status_dict, hour_dict in results:
        for status, cnt in status_dict.items():
            total_status[status] += cnt
        for hour, cnt in hour_dict.items():
            total_hours[hour] += cnt

    error_counts = {k: v for k, v in total_status.items() if k.startswith(('4', '5'))}
    hour_counts = dict(total_hours)
    return error_counts, hour_counts