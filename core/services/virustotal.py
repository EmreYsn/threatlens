import requests
from django.conf import settings


CATEGORIES = {
    'malicious': 'Kötü Amaçlı',
    'suspicious': 'Şüpheli',
    'harmless': 'Zararsız',
    'undetected': 'Tespit Edilemedi',
    'timeout': 'Zaman Aşımı',
}


def check_ip(ip_address):
    """VirusTotal IP address lookup"""
    api_key = getattr(settings, 'VIRUSTOTAL_API_KEY', '')
    if not api_key:
        return {'success': False, 'error': 'VirusTotal API key tanımlı değil'}

    try:
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
        headers = {'x-apikey': api_key}
        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code == 401:
            return {'success': False, 'error': 'Geçersiz API key'}
        if response.status_code == 429:
            return {'success': False, 'error': 'Rate limit aşıldı (VT: 4 istek/dk free)'}
        if response.status_code != 200:
            return {'success': False, 'error': f'HTTP {response.status_code}'}

        result = response.json()
        attrs = result.get('data', {}).get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})

        return {
            'success': True,
            'data': {
                'ip': ip_address,
                'as_owner': attrs.get('as_owner', ''),
                'asn': attrs.get('asn', 0),
                'country': attrs.get('country', ''),
                'network': attrs.get('network', ''),
                'reputation': attrs.get('reputation', 0),
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'timeout': stats.get('timeout', 0),
                'total_vendors': sum(stats.values()) if stats else 0,
                'last_analysis_stats': stats,
            }
        }

    except requests.exceptions.Timeout:
        return {'success': False, 'error': 'Bağlantı zaman aşımı'}
    except requests.exceptions.RequestException as e:
        return {'success': False, 'error': str(e)}


def check_domain(domain):
    """VirusTotal domain lookup"""
    api_key = getattr(settings, 'VIRUSTOTAL_API_KEY', '')
    if not api_key:
        return {'success': False, 'error': 'VirusTotal API key tanımlı değil'}

    try:
        url = f'https://www.virustotal.com/api/v3/domains/{domain}'
        headers = {'x-apikey': api_key}
        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code == 401:
            return {'success': False, 'error': 'Geçersiz API key'}
        if response.status_code == 429:
            return {'success': False, 'error': 'Rate limit aşıldı'}
        if response.status_code != 200:
            return {'success': False, 'error': f'HTTP {response.status_code}'}

        result = response.json()
        attrs = result.get('data', {}).get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        popularity = attrs.get('popularity_ranks', {})

        return {
            'success': True,
            'data': {
                'domain': domain,
                'registrar': attrs.get('registrar', ''),
                'creation_date': attrs.get('creation_date', 0),
                'reputation': attrs.get('reputation', 0),
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'total_vendors': sum(stats.values()) if stats else 0,
                'last_analysis_stats': stats,
                'categories': attrs.get('categories', {}),
                'popularity_ranks': popularity,
            }
        }

    except requests.exceptions.Timeout:
        return {'success': False, 'error': 'Bağlantı zaman aşımı'}
    except requests.exceptions.RequestException as e:
        return {'success': False, 'error': str(e)}


def check_url(url_to_check):
    """VirusTotal URL lookup (base64 encoded URL ID)"""
    import base64
    api_key = getattr(settings, 'VIRUSTOTAL_API_KEY', '')
    if not api_key:
        return {'success': False, 'error': 'VirusTotal API key tanımlı değil'}

    try:
        url_id = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip('=')
        url = f'https://www.virustotal.com/api/v3/urls/{url_id}'
        headers = {'x-apikey': api_key}
        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code == 404:
            # URL henüz taranmamış, scan başlat
            scan_url = 'https://www.virustotal.com/api/v3/urls'
            scan_resp = requests.post(
                scan_url, headers=headers,
                data={'url': url_to_check}, timeout=15
            )
            if scan_resp.status_code == 200:
                return {
                    'success': True,
                    'data': {
                        'url': url_to_check,
                        'malicious': 0,
                        'suspicious': 0,
                        'harmless': 0,
                        'undetected': 0,
                        'total_vendors': 0,
                        'scan_submitted': True,
                        'message': 'Tarama başlatıldı, sonuçlar birkaç dakika içinde hazır olacak',
                    }
                }
            return {'success': False, 'error': 'URL taraması başlatılamadı'}

        if response.status_code != 200:
            return {'success': False, 'error': f'HTTP {response.status_code}'}

        result = response.json()
        attrs = result.get('data', {}).get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})

        return {
            'success': True,
            'data': {
                'url': url_to_check,
                'final_url': attrs.get('last_final_url', url_to_check),
                'title': attrs.get('title', ''),
                'reputation': attrs.get('reputation', 0),
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'total_vendors': sum(stats.values()) if stats else 0,
                'last_analysis_stats': stats,
                'categories': attrs.get('categories', {}),
            }
        }

    except requests.exceptions.Timeout:
        return {'success': False, 'error': 'Bağlantı zaman aşımı'}
    except requests.exceptions.RequestException as e:
        return {'success': False, 'error': str(e)}


def check_hash(file_hash):
    """VirusTotal file hash lookup"""
    api_key = getattr(settings, 'VIRUSTOTAL_API_KEY', '')
    if not api_key:
        return {'success': False, 'error': 'VirusTotal API key tanımlı değil'}

    try:
        url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        headers = {'x-apikey': api_key}
        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code == 404:
            return {
                'success': True,
                'data': {
                    'hash': file_hash,
                    'found': False,
                    'malicious': 0,
                    'suspicious': 0,
                    'harmless': 0,
                    'undetected': 0,
                    'total_vendors': 0,
                    'message': 'Bu hash VirusTotal veritabanında bulunamadı',
                }
            }

        if response.status_code != 200:
            return {'success': False, 'error': f'HTTP {response.status_code}'}

        result = response.json()
        attrs = result.get('data', {}).get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})

        return {
            'success': True,
            'data': {
                'hash': file_hash,
                'found': True,
                'meaningful_name': attrs.get('meaningful_name', ''),
                'type_description': attrs.get('type_description', ''),
                'size': attrs.get('size', 0),
                'reputation': attrs.get('reputation', 0),
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'total_vendors': sum(stats.values()) if stats else 0,
                'last_analysis_stats': stats,
                'tags': attrs.get('tags', []),
                'popular_threat_names': _get_threat_names(attrs),
            }
        }

    except requests.exceptions.Timeout:
        return {'success': False, 'error': 'Bağlantı zaman aşımı'}
    except requests.exceptions.RequestException as e:
        return {'success': False, 'error': str(e)}
    
def _get_threat_names(attrs):
    """Threat classification'dan isimleri güvenli şekilde çıkar"""
    try:
        ptc = attrs.get('popular_threat_classification')
        if not ptc or not isinstance(ptc, dict):
            return []
        labels = ptc.get('suggested_threat_label')
        if not labels or not isinstance(labels, list):
            return []
        return [r.get('value', '') for r in labels if isinstance(r, dict)]
    except Exception:
        return []