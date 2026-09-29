"""
Alerting Module
===============
Sends alerts via multiple channels when thresholds are breached.

Supported channels:
- Slack (webhook)
- Discord (webhook)
- Telegram (bot)
- Email (SMTP)

Features:
- Severity levels (CRITICAL, HIGH, MEDIUM, LOW)
- Rate limiting (prevents duplicate alerts)
- Retry logic (network resilience)
- HTML email templates
- Configurable thresholds
"""

import os
import smtplib
import logging
import time
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import defaultdict
import requests


# =========================
# LOGGING SETUP
# =========================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


# =========================
# CONFIGURATION
# =========================
DEFAULT_THRESHOLDS = {
    'CRITICAL': 50,   # 50+ errors
    'HIGH': 20,       # 20-49 errors
    'MEDIUM': 10,     # 10-19 errors
    'LOW': 5          # 5-9 errors
}

# Rate limiting: don't send same alert more than once per hour
ALERT_COOLDOWN_MINUTES = 60

# Retry configuration
MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds

# Request timeout
REQUEST_TIMEOUT = 10  # seconds


# =========================
# ALERT HISTORY (in-memory rate limiting)
# =========================
_alert_history = defaultdict(lambda: datetime.min)


def _is_rate_limited(alert_key):
    """Check if alert was sent recently"""
    last_sent = _alert_history[alert_key]
    if datetime.now() - last_sent < timedelta(minutes=ALERT_COOLDOWN_MINUTES):
        return True
    return False


def _mark_alert_sent(alert_key):
    """Record that alert was sent"""
    _alert_history[alert_key] = datetime.now()


# =========================
# SEVERITY DETERMINATION
# =========================
def _get_severity(error_count):
    """Determine alert severity based on error count"""
    if error_count >= DEFAULT_THRESHOLDS['CRITICAL']:
        return 'CRITICAL'
    elif error_count >= DEFAULT_THRESHOLDS['HIGH']:
        return 'HIGH'
    elif error_count >= DEFAULT_THRESHOLDS['MEDIUM']:
        return 'MEDIUM'
    elif error_count >= DEFAULT_THRESHOLDS['LOW']:
        return 'LOW'
    return None


def _get_severity_emoji(severity):
    return {
        'CRITICAL': '🔴',
        'HIGH': '🟠',
        'MEDIUM': '🟡',
        'LOW': '🟢'
    }.get(severity, '⚪')


def _get_severity_color(severity):
    return {
        'CRITICAL': '#dc2626',
        'HIGH': '#ea580c',
        'MEDIUM': '#ca8a04',
        'LOW': '#16a34a'
    }.get(severity, '#64748b')


# =========================
# MESSAGE BUILDERS
# =========================
def _build_slack_message(error_count, filename, severity, error_counts, hour_counts):
    """Build Slack message with blocks"""
    emoji = _get_severity_emoji(severity)
    
    top_errors = sorted(error_counts.items(), key=lambda x: x[1], reverse=True)[:3]
    errors_text = "\n".join([f"• `{code}`: {count}" for code, count in top_errors])
    
    return {
        "text": f"{emoji} {severity} ALERT: {error_count} errors in {filename}",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} {severity} Log Alert"
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*File:*\n{filename}"},
                    {"type": "mrkdwn", "text": f"*Total Errors:*\n{error_count}"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"},
                    {"type": "mrkdwn", "text": f"*Time:*\n{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"}
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Top Errors:*\n{errors_text}"
                }
            }
        ]
    }


def _build_discord_message(error_count, filename, severity, error_counts):
    """Build Discord message with embeds"""
    emoji = _get_severity_emoji(severity)
    color = int(_get_severity_color(severity).replace('#', ''), 16)
    
    top_errors = sorted(error_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    errors_text = "\n".join([f"`{code}`: {count}" for code, count in top_errors])
    
    return {
        "content": f"{emoji} **{severity} ALERT**",
        "embeds": [{
            "title": f"Log Analysis Alert: {filename}",
            "description": f"**{error_count}** errors detected",
            "color": color,
            "fields": [
                {"name": "Severity", "value": severity, "inline": True},
                {"name": "File", "value": filename, "inline": True},
                {"name": "Top Errors", "value": errors_text or "N/A", "inline": False}
            ],
            "timestamp": datetime.utcnow().isoformat()
        }]
    }


def _build_email_html(error_count, filename, severity, error_counts, hour_counts):
    """Build HTML email body"""
    emoji = _get_severity_emoji(severity)
    color = _get_severity_color(severity)
    
    errors_rows = ""
    for code, count in sorted(error_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
        errors_rows += f"""
        <tr>
            <td style="padding: 8px; border-bottom: 1px solid #e2e8f0; font-family: monospace;">{code}</td>
            <td style="padding: 8px; border-bottom: 1px solid #e2e8f0; text-align: right;"><strong>{count}</strong></td>
        </tr>
        """
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head><meta charset="UTF-8"></head>
    <body style="font-family: Arial, sans-serif; background: #f8fafc; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <div style="background: {color}; padding: 24px; color: white; text-align: center;">
                <h1 style="margin: 0; font-size: 24px;">{emoji} {severity} Alert</h1>
                <p style="margin: 8px 0 0; opacity: 0.9;">Log Analysis Detected Anomalies</p>
            </div>
            
            <div style="padding: 24px;">
                <table style="width: 100%; margin-bottom: 20px;">
                    <tr><td style="padding: 8px 0;"><strong>File:</strong></td><td>{filename}</td></tr>
                    <tr><td style="padding: 8px 0;"><strong>Total Errors:</strong></td><td><span style="color: {color}; font-weight: bold; font-size: 20px;">{error_count}</span></td></tr>
                    <tr><td style="padding: 8px 0;"><strong>Severity:</strong></td><td><span style="background: {color}; color: white; padding: 4px 12px; border-radius: 12px;">{severity}</span></td></tr>
                    <tr><td style="padding: 8px 0;"><strong>Time:</strong></td><td>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
                </table>
                
                <h3 style="color: #1e293b; margin-top: 24px;">Top Errors</h3>
                <table style="width: 100%; border-collapse: collapse; background: #f8fafc; border-radius: 8px; overflow: hidden;">
                    <thead>
                        <tr style="background: #1e293b; color: white;">
                            <th style="padding: 10px; text-align: left;">Code</th>
                            <th style="padding: 10px; text-align: right;">Count</th>
                        </tr>
                    </thead>
                    <tbody>
                        {errors_rows}
                    </tbody>
                </table>
            </div>
            
            <div style="padding: 16px; background: #f1f5f9; text-align: center; color: #64748b; font-size: 12px;">
                Secure Log Analyzer &mdash; Automated Alert System
            </div>
        </div>
    </body>
    </html>
    """


# =========================
# CHANNEL SENDERS
# =========================
def send_slack_alert(error_count, filename, severity, error_counts, hour_counts):
    """Send alert to Slack"""
    webhook_url = os.getenv('SLACK_WEBHOOK_URL')
    if not webhook_url:
        logger.debug("Slack webhook not configured, skipping")
        return False
    
    message = _build_slack_message(error_count, filename, severity, error_counts, hour_counts)
    
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.post(
                webhook_url,
                json=message,
                timeout=REQUEST_TIMEOUT
            )
            if response.status_code == 200:
                logger.info(f"✅ Slack alert sent ({severity}: {error_count} errors)")
                return True
            else:
                logger.warning(f"Slack returned {response.status_code}: {response.text[:100]}")
        except requests.exceptions.RequestException as e:
            logger.warning(f"Slack attempt {attempt+1} failed: {e}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
    
    logger.error("❌ Slack alert failed after all retries")
    return False


def send_discord_alert(error_count, filename, severity, error_counts):
    """Send alert to Discord"""
    webhook_url = os.getenv('DISCORD_WEBHOOK_URL')
    if not webhook_url:
        logger.debug("Discord webhook not configured, skipping")
        return False
    
    message = _build_discord_message(error_count, filename, severity, error_counts)
    
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.post(
                webhook_url,
                json=message,
                timeout=REQUEST_TIMEOUT
            )
            if response.status_code in (200, 204):
                logger.info(f"✅ Discord alert sent ({severity}: {error_count} errors)")
                return True
        except requests.exceptions.RequestException as e:
            logger.warning(f"Discord attempt {attempt+1} failed: {e}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
    
    logger.error("❌ Discord alert failed")
    return False


def send_telegram_alert(error_count, filename, severity, error_counts):
    """Send alert to Telegram"""
    bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
    chat_id = os.getenv('TELEGRAM_CHAT_ID')
    
    if not all([bot_token, chat_id]):
        logger.debug("Telegram not configured, skipping")
        return False
    
    emoji = _get_severity_emoji(severity)
    top_errors = sorted(error_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    errors_text = "\n".join([f"• {code}: {count}" for code, count in top_errors])
    
    message = (
        f"{emoji} *{severity} ALERT*\n\n"
        f"*File:* `{filename}`\n"
        f"*Errors:* {error_count}\n\n"
        f"*Top Errors:*\n{errors_text}"
    )
    
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        'chat_id': chat_id,
        'text': message,
        'parse_mode': 'Markdown'
    }
    
    try:
        response = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            logger.info(f"✅ Telegram alert sent")
            return True
    except requests.exceptions.RequestException as e:
        logger.warning(f"Telegram failed: {e}")
    
    return False


def send_email_alert(error_count, filename, severity, error_counts, hour_counts):
    """Send HTML email alert"""
    email_user = os.getenv('ALERT_EMAIL')
    email_pass = os.getenv('ALERT_EMAIL_PASSWORD')
    admin_email = os.getenv('ADMIN_EMAIL')
    smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
    smtp_port = int(os.getenv('SMTP_PORT', 587))
    
    if not all([email_user, email_pass, admin_email]):
        logger.debug("Email not configured, skipping")
        return False
    
    emoji = _get_severity_emoji(severity)
    
    msg = MIMEMultipart('alternative')
    msg['Subject'] = f"{emoji} {severity} Alert: {error_count} errors in {filename}"
    msg['From'] = email_user
    msg['To'] = admin_email
    
    # Plain text fallback
    text = f"""
{severity} ALERT

File: {filename}
Total Errors: {error_count}
Severity: {severity}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
    msg.attach(MIMEText(text, 'plain'))
    
    # HTML version
    html = _build_email_html(error_count, filename, severity, error_counts, hour_counts)
    msg.attach(MIMEText(html, 'html'))
    
    for attempt in range(MAX_RETRIES):
        try:
            with smtplib.SMTP(smtp_server, smtp_port, timeout=REQUEST_TIMEOUT) as server:
                server.starttls()
                server.login(email_user, email_pass)
                server.send_message(msg)
            logger.info(f"✅ Email alert sent to {admin_email}")
            return True
        except smtplib.SMTPException as e:
            logger.warning(f"Email attempt {attempt+1} failed: {e}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
    
    logger.error("❌ Email alert failed")
    return False


# =========================
# MAIN FUNCTION
# =========================
def check_and_alert(error_counts, hour_counts, filename, force=False):
    """
    Main alert checking function.
    
    Args:
        error_counts (dict): {status_code: count}
        hour_counts (dict): {hour: count}
        filename (str): Name of analyzed file
        force (bool): Skip rate limiting (useful for testing)
    
    Returns:
        dict: Summary of alerts sent
    """
    if not error_counts:
        return {'status': 'no_errors'}
    
    total_errors = sum(error_counts.values())
    severity = _get_severity(total_errors)
    
    # No alert if below threshold
    if not severity:
        logger.debug(f"No alert: {total_errors} errors below threshold")
        return {'status': 'below_threshold', 'total_errors': total_errors}
    
    # Rate limiting check
    alert_key = f"{filename}:{severity}"
    if not force and _is_rate_limited(alert_key):
        logger.info(f"⏸ Alert rate limited for {alert_key}")
        return {'status': 'rate_limited', 'total_errors': total_errors}
    
    logger.info(f"🚨 Triggering {severity} alert: {total_errors} errors in {filename}")
    
    # Send to all configured channels
    results = {
        'severity': severity,
        'total_errors': total_errors,
        'filename': filename,
        'channels': {}
    }
    
    results['channels']['slack'] = send_slack_alert(
        total_errors, filename, severity, error_counts, hour_counts
    )
    
    results['channels']['discord'] = send_discord_alert(
        total_errors, filename, severity, error_counts
    )
    
    results['channels']['telegram'] = send_telegram_alert(
        total_errors, filename, severity, error_counts
    )
    
    results['channels']['email'] = send_email_alert(
        total_errors, filename, severity, error_counts, hour_counts
    )
    
    # Mark as sent for rate limiting
    _mark_alert_sent(alert_key)
    
    sent_count = sum(1 for v in results['channels'].values() if v)
    logger.info(f"📤 Alert sent to {sent_count} channel(s)")
    
    return results


# =========================
# TESTING
# =========================
if __name__ == '__main__':
    print("=" * 60)
    print("ALERT SYSTEM TEST")
    print("=" * 60)
    
    test_errors = {'404': 30, '500': 25, '403': 10}
    test_hours = {'9': 10, '14': 50, '15': 45}
    
    print(f"\nTest data:")
    print(f"  Errors: {test_errors}")
    print(f"  Total: {sum(test_errors.values())}")
    
    result = check_and_alert(test_hours=test_hours, error_counts=test_errors, 
                            filename='test.log', force=True)
    
    print(f"\nResult:")
    print(f"  Severity: {result.get('severity')}")
    print(f"  Channels: {result.get('channels')}")