import requests
from django.conf import settings


def check_ip(ip_address):
    """AlienVault OTX - IP reputation lookup"""
    api_key = getattr(settings, 'ALIENVAULT_API_KEY', '')

    try:
        headers = {}
        if api_key:
            headers['X-OTX-API-KEY'] = api_key

        # Genel bilgiler
        url = f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general'
        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code != 200:
            return {'success': False, 'error': f'HTTP {response.status_code}'}

        data = response.json()
        pulse_count = data.get('pulse_info', {}).get('count', 0)
        pulses = data.get('pulse_info', {}).get('pulses', [])

        # İlk 5 pulse'un isimlerini al
        pulse_names = [p.get('name', '') for p in pulses[:5]]

        # Reputation bilgisi
        reputation = data.get('reputation', None)
        threat_score = 0
        activities = []

        if reputation:
            threat_score = reputation.get('threat_score', 0)
            activities = [
                a.get('name', '') for a in
                reputation.get('activities', [])
            ]

        # Ülke bilgisi
        country = data.get('country_name', '')
        country_code = data.get('country_code', '')
        asn = data.get('asn', '')

        return {
            'success': True,
            'data': {
                'ip': ip_address,
                'pulse_count': pulse_count,
                'pulse_names': pulse_names,
                'threat_score': threat_score,
                'activities': activities,
                'country': country,
                'country_code': country_code,
                'asn': asn,
                'reputation': reputation or {},
                'sections': data.get('sections', []),
            }
        }

    except requests.exceptions.Timeout:
        return {'success': False, 'error': 'Bağlantı zaman aşımı'}
    except requests.exceptions.RequestException as e:
        return {'success': False, 'error': str(e)}


def check_domain(domain):
    """AlienVault OTX - Domain lookup"""
    api_key = getattr(settings, 'ALIENVAULT_API_KEY', '')

    try:
        headers = {}
        if api_key:
            headers['X-OTX-API-KEY'] = api_key

        url = f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general'
        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code != 200:
            return {'success': False, 'error': f'HTTP {response.status_code}'}

        data = response.json()
        pulse_count = data.get('pulse_info', {}).get('count', 0)
        pulses = data.get('pulse_info', {}).get('pulses', [])
        pulse_names = [p.get('name', '') for p in pulses[:5]]

        return {
            'success': True,
            'data': {
                'domain': domain,
                'pulse_count': pulse_count,
                'pulse_names': pulse_names,
                'alexa': data.get('alexa', ''),
                'whois': data.get('whois', ''),
            }
        }

    except requests.exceptions.Timeout:
        return {'success': False, 'error': 'Bağlantı zaman aşımı'}
    except requests.exceptions.RequestException as e:
        return {'success': False, 'error': str(e)}


def check_hash(file_hash):
    """AlienVault OTX - File hash lookup"""
    api_key = getattr(settings, 'ALIENVAULT_API_KEY', '')

    try:
        headers = {}
        if api_key:
            headers['X-OTX-API-KEY'] = api_key

        url = f'https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general'
        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code == 404:
            return {
                'success': True,
                'data': {
                    'hash': file_hash,
                    'found': False,
                    'pulse_count': 0,
                    'pulse_names': [],
                }
            }

        if response.status_code != 200:
            return {'success': False, 'error': f'HTTP {response.status_code}'}

        data = response.json()
        pulse_count = data.get('pulse_info', {}).get('count', 0)
        pulses = data.get('pulse_info', {}).get('pulses', [])
        pulse_names = [p.get('name', '') for p in pulses[:5]]

        return {
            'success': True,
            'data': {
                'hash': file_hash,
                'found': True,
                'pulse_count': pulse_count,
                'pulse_names': pulse_names,
                'malware_families': data.get('malware_families', []),
            }
        }

    except requests.exceptions.Timeout:
        return {'success': False, 'error': 'Bağlantı zaman aşımı'}
    except requests.exceptions.RequestException as e:
        return {'success': False, 'error': str(e)}