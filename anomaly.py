"""
Anomaly Detection Module
========================
Detects unusual patterns in log analysis using:
1. Isolation Forest (ML-based)
2. Z-Score (statistical)
3. Threshold-based rules

Returns prioritized anomalies with severity levels.
"""

import numpy as np

# Optional: scikit-learn
try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("⚠️ scikit-learn not installed. Using Z-Score only.")


# =========================
# CONFIGURATION
# =========================
MIN_DATA_POINTS = 3              # Minimum hours needed for ML
MIN_TRAFFIC_THRESHOLD = 5        # Hours with < 5 requests ignored
HIGH_ERROR_RATE = 20.0           # Error rate > 20% is suspicious
CRITICAL_ERROR_RATE = 50.0       # Error rate > 50% is critical

# Night hours (usually low traffic expected)
NIGHT_HOURS = {0, 1, 2, 3, 4, 5}


# =========================
# HELPER FUNCTIONS
# =========================
def _sort_hours(hours):
    """Sort hour strings numerically (e.g., '9' before '14')"""
    return sorted(hours, key=lambda h: int(h))


def _calculate_z_scores(counts):
    """Calculate Z-scores for each value"""
    if len(counts) < 2:
        return np.zeros(len(counts))
    
    mean = np.mean(counts)
    std = np.std(counts)
    
    if std == 0:
        return np.zeros(len(counts))
    
    return (counts - mean) / std


def _get_severity(z_score=None, error_rate=None, hour=None):
    """Determine severity level"""
    if error_rate is not None:
        if error_rate >= CRITICAL_ERROR_RATE:
            return 'CRITICAL'
        elif error_rate >= HIGH_ERROR_RATE:
            return 'HIGH'
    
    if z_score is not None:
        abs_z = abs(z_score)
        if abs_z >= 3:
            return 'CRITICAL'
        elif abs_z >= 2.5:
            return 'HIGH'
        elif abs_z >= 2:
            return 'MEDIUM'
    
    return 'LOW'


def _get_reason(z_score, hour, count, mean, std):
    """Generate human-readable reason"""
    hour_int = int(hour) if hour is not None else -1
    
    if z_score > 0:
        # More traffic than expected
        if hour_int in NIGHT_HOURS:
            return f"Unusual high traffic during night ({hour}:00) — possible attack"
        return f"Traffic spike: {count} requests (avg: {mean:.1f}, +{z_score:.1f}σ)"
    else:
        # Less traffic than expected
        if hour_int not in NIGHT_HOURS:
            return f"Traffic drop: only {count} requests (avg: {mean:.1f}, {z_score:.1f}σ)"
        return f"Low activity during peak hours"


# =========================
# METHOD 1: ISOLATION FOREST (ML)
# =========================
def detect_with_isolation_forest(hour_counts, contamination='auto'):
    """Detect anomalies using Isolation Forest"""
    if not SKLEARN_AVAILABLE or len(hour_counts) < MIN_DATA_POINTS:
        return []
    
    hours = _sort_hours(hour_counts.keys())
    counts = np.array([hour_counts[h] for h in hours]).reshape(-1, 1)
    
    try:
        model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        predictions = model.fit_predict(counts)
        scores = model.score_samples(counts)
        
        anomalies = []
        for i, pred in enumerate(predictions):
            if pred == -1:
                anomalies.append({
                    'hour': hours[i],
                    'count': hour_counts[hours[i]],
                    'method': 'IsolationForest',
                    'score': round(float(scores[i]), 3)
                })
        
        return anomalies
    except Exception as e:
        print(f"Isolation Forest failed: {e}")
        return []


# =========================
# METHOD 2: Z-SCORE (STATISTICAL)
# =========================
def detect_with_z_score(hour_counts, threshold=2.0):
    """Detect anomalies using Z-Score"""
    if len(hour_counts) < MIN_DATA_POINTS:
        return []
    
    hours = _sort_hours(hour_counts.keys())
    counts = np.array([hour_counts[h] for h in hours])
    
    z_scores = _calculate_z_scores(counts)
    mean = float(np.mean(counts))
    std = float(np.std(counts))
    
    anomalies = []
    for i, z in enumerate(z_scores):
        if abs(z) >= threshold:
            anomalies.append({
                'hour': hours[i],
                'count': int(counts[i]),
                'z_score': round(float(z), 2),
                'mean': round(mean, 2),
                'std': round(std, 2),
                'method': 'Z-Score',
                'severity': _get_severity(z_score=z),
                'reason': _get_reason(z, hours[i], int(counts[i]), mean, std)
            })
    
    return anomalies


# =========================
# METHOD 3: ERROR RATE DETECTION
# =========================
def detect_high_error_rate(error_counts, hour_counts):
    """Detect if overall error rate is unusually high"""
    total_errors = sum(error_counts.values()) if error_counts else 0
    total_requests = sum(hour_counts.values()) if hour_counts else 0
    
    if total_requests == 0:
        return []
    
    error_rate = (total_errors / total_requests) * 100
    
    if error_rate >= HIGH_ERROR_RATE:
        severity = 'CRITICAL' if error_rate >= CRITICAL_ERROR_RATE else 'HIGH'
        return [{
            'type': 'error_rate',
            'error_rate': round(error_rate, 2),
            'total_errors': total_errors,
            'total_requests': total_requests,
            'severity': severity,
            'reason': f"Error rate is {error_rate:.1f}% ({total_errors}/{total_requests})"
        }]
    
    return []


# =========================
# METHOD 4: SPIKY ERROR CODE DETECTION
# =========================
def detect_dominant_errors(error_counts, threshold=0.5):
    """Detect if one error type dominates"""
    if not error_counts:
        return []
    
    total = sum(error_counts.values())
    if total == 0:
        return []
    
    anomalies = []
    for code, count in error_counts.items():
        ratio = count / total
        if ratio >= threshold and count >= 5:
            anomalies.append({
                'type': 'dominant_error',
                'code': code,
                'count': count,
                'ratio': round(ratio * 100, 1),
                'severity': 'HIGH' if ratio >= 0.8 else 'MEDIUM',
                'reason': f"{code} accounts for {ratio*100:.1f}% of all errors"
            })
    
    return anomalies


# =========================
# MAIN FUNCTION
# =========================
def detect_anomalies(hour_counts, error_counts=None, method='hybrid'):
    """
    Main anomaly detection function.
    
    Args:
        hour_counts (dict): {hour_str: count}
        error_counts (dict): {status_code: count}  (optional)
        method (str): 'ml', 'zscore', or 'hybrid'
    
    Returns:
        list: Sorted list of anomalies with severity, reason, and metadata
    """
    if not hour_counts or len(hour_counts) < MIN_DATA_POINTS:
        return []
    
    all_anomalies = []
    
    # Clean data: remove hours with very low traffic
    filtered_hours = {
        h: c for h, c in hour_counts.items()
        if c >= MIN_TRAFFIC_THRESHOLD
    }
    
    # If too few data points after filtering, use original
    if len(filtered_hours) < MIN_DATA_POINTS:
        filtered_hours = hour_counts
    
    # -------- Method 1: Isolation Forest --------
    if method in ('ml', 'hybrid') and SKLEARN_AVAILABLE:
        ml_anomalies = detect_with_isolation_forest(filtered_hours)
        for a in ml_anomalies:
            a['severity'] = _get_severity(hour=a['hour'])
            a['reason'] = f"ML detected unusual pattern at {a['hour']}:00 ({a['count']} requests)"
        all_anomalies.extend(ml_anomalies)
    
    # -------- Method 2: Z-Score --------
    if method in ('zscore', 'hybrid'):
        z_anomalies = detect_with_z_score(filtered_hours)
        
        # Avoid duplicates (same hour already detected by ML)
        existing_hours = {a['hour'] for a in all_anomalies}
        for a in z_anomalies:
            if a['hour'] not in existing_hours:
                all_anomalies.append(a)
    
    # -------- Method 3: Error Rate --------
    if error_counts:
        error_anomalies = detect_high_error_rate(error_counts, hour_counts)
        all_anomalies.extend(error_anomalies)
        
        # -------- Method 4: Dominant Errors --------
        dominant_anomalies = detect_dominant_errors(error_counts)
        all_anomalies.extend(dominant_anomalies)
    
    # -------- Sort by severity --------
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    all_anomalies.sort(key=lambda x: severity_order.get(x.get('severity', 'LOW'), 4))
    
    # -------- Limit to top 10 --------
    return all_anomalies[:10]


# =========================
# SUMMARY HELPER
# =========================
def get_anomaly_summary(anomalies):
    """Return summary counts by severity"""
    summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for a in anomalies:
        severity = a.get('severity', 'LOW')
        summary[severity] = summary.get(severity, 0) + 1
    return summary


# =========================
# TESTING (Run directly)
# =========================
if __name__ == '__main__':
    test_hours = {
        '9': 10, '10': 12, '11': 15, '12': 14,
        '13': 13, '14': 100, '15': 95, '16': 11,
        '22': 8, '23': 5
    }
    test_errors = {'404': 45, '500': 30, '403': 5}
    
    print("=" * 60)
    print("ANOMALY DETECTION TEST")
    print("=" * 60)
    
    anomalies = detect_anomalies(test_hours, test_errors)
    
    print(f"\n🎯 Found {len(anomalies)} anomalies:\n")
    for a in anomalies:
        print(f"  [{a.get('severity', 'LOW')}] {a.get('reason', a.get('type'))}")
    
    print("\n📊 Summary:", get_anomaly_summary(anomalies))