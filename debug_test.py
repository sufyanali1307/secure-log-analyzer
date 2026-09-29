"""
Debug script to check log parsing and analysis
"""
import os
import re
from collections import Counter

LOG_FILE = 'test.log'

print("=" * 60)
print("DEBUG: Secure Log Analyzer")
print("=" * 60)

# 1. Check file
if not os.path.exists(LOG_FILE):
    print(f"❌ File not found: {LOG_FILE}")
    exit(1)

with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
    lines = f.readlines()

print(f"\n✅ Total lines: {len(lines)}")
print(f"\n📄 First 3 lines:")
for line in lines[:3]:
    print(f"   {line.strip()}")

# 2. Try Apache Combined Log Format
APACHE_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+-\s+-\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<url>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d+)\s+'
    r'(?P<size>\d+)'
)

matched = 0
unmatched = 0
hours = []
statuses = []
urls = []

for line in lines:
    m = APACHE_PATTERN.match(line.strip())
    if m:
        matched += 1
        ts = m.group('timestamp')  # e.g., 29/Sep/2026:09:15:23 +0500
        # Extract hour
        hour_match = re.search(r':(\d{2}):', ts)
        if hour_match:
            hours.append(hour_match.group(1))
        statuses.append(m.group('status'))
        urls.append(m.group('url'))
    else:
        unmatched += 1

print(f"\n📊 Parse Results:")
print(f"   ✅ Matched: {matched}")
print(f"   ❌ Unmatched: {unmatched}")

if matched == 0:
    print("\n🔴 PARSING FAILED! Log format doesn't match Apache Combined format.")
    print("   Check your log format in app.py / mapreduce.py")
    exit(1)

# 3. Hour distribution
hour_counts = Counter(hours)
print(f"\n⏰ Hourly Traffic Distribution:")
for h in sorted(hour_counts.keys()):
    bar = '█' * hour_counts[h]
    print(f"   {h}:00 → {hour_counts[h]:3d}  {bar}")

# 4. Error distribution
error_counts = Counter(s for s in statuses if s.startswith(('4', '5')))
print(f"\n🚨 Error Distribution:")
if error_counts:
    for code in sorted(error_counts.keys()):
        print(f"   HTTP {code}: {error_counts[code]}")
else:
    print("   (No errors found)")

# 5. Top URLs
url_counts = Counter(urls)
print(f"\n🌐 Top 10 URLs:")
for url, count in url_counts.most_common(10):
    print(f"   {url}: {count}")

print("\n" + "=" * 60)
print("✅ If data shows here, parsing works. Problem is in GUI/frontend.")
print("❌ If data missing, problem is in app.py parser.")
print("=" * 60)