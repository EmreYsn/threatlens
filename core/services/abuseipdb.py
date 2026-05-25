"""
AbuseIPDB API Servisi
https://docs.abuseipdb.com/

IP adreslerinin itibar skorunu, şikayet geçmişini ve raporlarını çeker.
Ücretsiz plan: günlük 1000 istek.
"""

import logging
import requests
from django.conf import settings

logger = logging.getLogger(__name__)

ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
TIMEOUT = 15  # saniye


def check_ip(ip_address: str) -> dict:
    """
    AbuseIPDB'den IP adresinin itibar raporunu çeker.

    Returns:
        {
            'success': bool,
            'data': {
                'ip': str,
                'is_public': bool,
                'abuse_confidence_score': int (0-100),
                'country_code': str,
                'isp': str,
                'domain': str,
                'total_reports': int,
                'last_reported_at': str | None,
                'usage_type': str,
                ...
            },
            'error': str | None
        }
    """
    api_key = settings.ABUSEIPDB_API_KEY
    if not api_key:
        return {
            'success': False,
            'data': {},
            'error': 'AbuseIPDB API anahtarı tanımlı değil. .env dosyasını kontrol edin.'
        }

    headers = {
        'Key': api_key,
        'Accept': 'application/json',
    }

    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': 90,
        'verbose': '',
    }

    try:
        response = requests.get(
            f"{ABUSEIPDB_BASE_URL}/check",
            headers=headers,
            params=params,
            timeout=TIMEOUT,
        )

        if response.status_code == 200:
            result = response.json()
            data = result.get('data', {})
            return {
                'success': True,
                'data': {
                    'ip': data.get('ipAddress', ip_address),
                    'is_public': data.get('isPublic', True),
                    'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                    'country_code': data.get('countryCode', ''),
                    'country_name': data.get('countryName', ''),
                    'isp': data.get('isp', ''),
                    'domain': data.get('domain', ''),
                    'total_reports': data.get('totalReports', 0),
                    'num_distinct_users': data.get('numDistinctUsers', 0),
                    'last_reported_at': data.get('lastReportedAt'),
                    'usage_type': data.get('usageType', ''),
                    'is_tor': data.get('isTor', False),
                    'is_whitelisted': data.get('isWhitelisted', False),
                },
                'error': None,
            }

        elif response.status_code == 401:
            return {
                'success': False,
                'data': {},
                'error': 'AbuseIPDB API anahtarı geçersiz.',
            }

        elif response.status_code == 429:
            return {
                'success': False,
                'data': {},
                'error': 'AbuseIPDB günlük istek limiti aşıldı.',
            }

        else:
            return {
                'success': False,
                'data': {},
                'error': f'AbuseIPDB hatası: HTTP {response.status_code}',
            }

    except requests.exceptions.Timeout:
        return {
            'success': False,
            'data': {},
            'error': 'AbuseIPDB isteği zaman aşımına uğradı.',
        }
    except requests.exceptions.ConnectionError:
        return {
            'success': False,
            'data': {},
            'error': 'AbuseIPDB sunucusuna bağlanılamadı.',
        }
    except Exception as e:
        logger.exception("AbuseIPDB check_ip hatası")
        return {
            'success': False,
            'data': {},
            'error': f'Beklenmeyen hata: {str(e)}',
        }


def get_abuse_categories() -> dict:
    """AbuseIPDB şikayet kategorileri"""
    return {
        1: 'DNS Compromise',
        2: 'DNS Poisoning',
        3: 'Fraud Orders',
        4: 'DDoS Attack',
        5: 'FTP Brute-Force',
        6: 'Ping of Death',
        7: 'Phishing',
        8: 'Fraud VoIP',
        9: 'Open Proxy',
        10: 'Web Spam',
        11: 'Email Spam',
        12: 'Blog Spam',
        13: 'VPN IP',
        14: 'Port Scan',
        15: 'Hacking',
        16: 'SQL Injection',
        17: 'Spoofing',
        18: 'Brute-Force',
        19: 'Bad Web Bot',
        20: 'Exploited Host',
        21: 'Web App Attack',
        22: 'SSH',
        23: 'IoT Targeted',
    }
