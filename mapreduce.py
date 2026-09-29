import os
import re
import json
import multiprocessing as mp
from collections import defaultdict


# =========================
# GEOIP SETUP (Optional)
# =========================
GEOIP_AVAILABLE = False
geoip_reader = None

try:
    import geoip2.database
    GEOIP_DB_PATH = os.path.join(os.path.dirname(__file__), 'GeoLite2-Country.mmdb')
    if os.path.exists(GEOIP_DB_PATH):
        geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
        GEOIP_AVAILABLE = True
        print("✅ GeoIP database loaded")
    else:
        print("⚠️ GeoLite2-Country.mmdb not found. Country detection disabled.")
except ImportError:
    print("⚠️ geoip2 not installed. Country detection disabled.")


# =========================
# TIMESTAMP PARSING
# =========================
def extract_hour_from_timestamp(timestamp):
    """Extract hour (0-23) from any timestamp format"""
    if not timestamp:
        return None
    
    timestamp = str(timestamp)
    
    match = re.search(r'T(\d{2}):', timestamp)
    if match:
        return int(match.group(1))
    
    match = re.search(r'\s(\d{2}):\d{2}:\d{2}', timestamp)
    if match:
        return int(match.group(1))
    
    match = re.search(r'(\d{2}):\d{2}:\d{2}', timestamp)
    if match:
        return int(match.group(1))
    
    return None


def extract_ip(line):
    """Extract IP address from log line"""
    match = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
    if match:
        return match.group(1)
    return None


def get_country(ip):
    """Look up country code from IP"""
    if not GEOIP_AVAILABLE or not ip:
        return None
    try:
        response = geoip_reader.country(ip)
        return response.country.iso_code
    except Exception:
        return None


# =========================
# MULTI-FORMAT PARSER
# =========================
def parse_log_line(line):
    """
    Parse a single log line and return:
    (status_code, hour, url, ip, country)
    """
    line = line.strip()
    if not line:
        return None, None, None, None, None
    
    status = None
    hour = None
    url = None
    ip = None
    country = None
    
    # Format 1: JSON logs
    if line.startswith('{'):
        try:
            data = json.loads(line)
            status = str(
                data.get('status') or
                data.get('status_code') or
                data.get('level') or
                ''
            ) or None
            
            timestamp = (
                data.get('timestamp') or
                data.get('time') or
                data.get('@timestamp') or
                ''
            )
            hour = extract_hour_from_timestamp(timestamp)
            
            url = data.get('url') or data.get('path') or data.get('endpoint')
            ip = data.get('ip') or data.get('remote_addr') or data.get('client_ip')
            
            if ip:
                country = get_country(ip)
            
            return status, hour, url, ip, country
        except (json.JSONDecodeError, TypeError):
            pass
    
    # Format 2: Apache/Nginx Common Log Format
    apache_pattern = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\S+\s+\S+\s+\[(\d+/\w+/\d+):(\d{2}):\d{2}:\d{2}\s+[+-]\d{4}\]\s+"(\w+)\s+(\S+)\s+\S+"\s+(\d{3})'
    match = re.search(apache_pattern, line)
    if match:
        ip = match.group(1)
        hour = int(match.group(3))
        url = match.group(5)
        status = match.group(6)
        country = get_country(ip)
        return status, hour, url, ip, country
    
    # Format 3: Syslog
    syslog_pattern = r'^(\w{3})\s+(\d+)\s+(\d{2}):(\d{2}):(\d{2})'
    match = re.search(syslog_pattern, line)
    if match:
        hour = int(match.group(3))
        
        if re.search(r'\b(error|fail|failed|failure)\b', line, re.IGNORECASE):
            status = 'ERROR'
        elif re.search(r'\b(warn|warning)\b', line, re.IGNORECASE):
            status = 'WARN'
        elif re.search(r'\b(critical|fatal|emerg)\b', line, re.IGNORECASE):
            status = 'CRITICAL'
        
        return status, hour, None, None, None
    
    # Format 4: ISO Timestamp
    iso_pattern = r'(\d{4}-\d{2}-\d{2})[T ](\d{2}):\d{2}:\d{2}'
    match = re.search(iso_pattern, line)
    if match:
        hour = int(match.group(2))
        
        status_match = re.search(r'\b(\d{3})\b', line)
        if status_match:
            status = status_match.group(1)
        else:
            level_match = re.search(r'\b(ERROR|WARN|WARNING|INFO|DEBUG|FATAL|CRITICAL)\b', line, re.IGNORECASE)
            if level_match:
                level = level_match.group(1).upper()
                status = 'WARN' if level == 'WARNING' else level
        
        url_match = re.search(r'(?:GET|POST|PUT|DELETE|PATCH)\s+(\S+)', line)
        if url_match:
            url = url_match.group(1)
        
        return status, hour, url, None, None
    
    # Fallback: just look for status code
    status_match = re.search(r'\b([45]\d{2})\b', line)
    if status_match:
        status = status_match.group(1)
    
    return status, hour, url, ip, country


# =========================
# MAP FUNCTION
# =========================
def map_chunk(chunk_lines):
    """Process a chunk of lines"""
    status_counts = defaultdict(int)
    hour_counts = defaultdict(int)
    url_counts = defaultdict(int)
    country_counts = defaultdict(int)
    
    for line in chunk_lines:
        status, hour, url, ip, country = parse_log_line(line)
        
        if status:
            status_counts[status] += 1
        if hour is not None:
            hour_counts[str(hour)] += 1
        if url:
            url_counts[url] += 1
        if country:
            country_counts[country] += 1
    
    return dict(status_counts), dict(hour_counts), dict(url_counts), dict(country_counts)


# =========================
# MAIN MAPREDUCE
# =========================
def run_mapreduce(file_path, num_workers=None):
    """
    Execute full MapReduce workflow:
    Split → Map → Shuffle → Reduce
    
    Returns:
        (error_counts, hour_counts, url_counts, country_counts)
    """
    # SPLIT
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    if not lines:
        return {}, {}, {}, {}
    
    total_lines = len(lines)
    
    if num_workers is None:
        num_workers = min(mp.cpu_count(), max(1, total_lines // 1000))
    
    chunk_size = max(1, total_lines // num_workers)
    chunks = [lines[i:i + chunk_size] for i in range(0, total_lines, chunk_size)]
    
    print(f"📊 Split: {total_lines} lines → {len(chunks)} chunks ({num_workers} workers)")
    
    # MAP (parallel)
    try:
        with mp.Pool(processes=num_workers) as pool:
            results = pool.map(map_chunk, chunks)
    except Exception as e:
        print(f"⚠️ Multiprocessing failed, falling back to sequential: {e}")
        results = [map_chunk(chunk) for chunk in chunks]
    
    # SHUFFLE & REDUCE
    total_status = defaultdict(int)
    total_hours = defaultdict(int)
    total_urls = defaultdict(int)
    total_countries = defaultdict(int)
    
    for status_dict, hour_dict, url_dict, country_dict in results:
        for k, v in status_dict.items():
            total_status[k] += v
        for k, v in hour_dict.items():
            total_hours[k] += v
        for k, v in url_dict.items():
            total_urls[k] += v
        for k, v in country_dict.items():
            total_countries[k] += v
    
    # Filter HTTP errors
    error_counts = {
        k: v for k, v in total_status.items()
        if k and (k.startswith('4') or k.startswith('5') or k in ('ERROR', 'FATAL', 'CRITICAL'))
    }
    
    hour_counts = dict(total_hours)
    top_urls = dict(sorted(total_urls.items(), key=lambda x: x[1], reverse=True)[:50])
    country_counts = dict(total_countries)
    
    print(f"✅ Reduce: {len(error_counts)} errors, {len(hour_counts)} hours, "
          f"{len(top_urls)} URLs, {len(country_counts)} countries")
    
    return error_counts, hour_counts, top_urls, country_counts