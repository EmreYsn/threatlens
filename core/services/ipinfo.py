import requests
from django.conf import settings


def check_ip(ip_address):
    """ipinfo.io IP geolocation + ASN lookup"""
    api_key = getattr(settings, 'IPINFO_API_KEY', '')

    try:
        url = f'https://ipinfo.io/{ip_address}/json'
        params = {}
        if api_key:
            params['token'] = api_key

        response = requests.get(url, params=params, timeout=10)

        if response.status_code == 429:
            return {'success': False, 'error': 'Rate limit aşıldı'}
        if response.status_code != 200:
            return {'success': False, 'error': f'HTTP {response.status_code}'}

        data = response.json()

        # Koordinatları ayır
        loc = data.get('loc', '')
        lat, lon = None, None
        if loc and ',' in loc:
            parts = loc.split(',')
            try:
                lat = float(parts[0])
                lon = float(parts[1])
            except (ValueError, IndexError):
                pass

        # ASN bilgisini parse et
        org = data.get('org', '')
        asn = ''
        org_name = org
        if org.startswith('AS'):
            parts = org.split(' ', 1)
            asn = parts[0]
            org_name = parts[1] if len(parts) > 1 else ''

        return {
            'success': True,
            'data': {
                'ip': data.get('ip', ip_address),
                'hostname': data.get('hostname', ''),
                'city': data.get('city', ''),
                'region': data.get('region', ''),
                'country': data.get('country', ''),
                'country_name': _country_name(data.get('country', '')),
                'loc': loc,
                'latitude': lat,
                'longitude': lon,
                'org': org,
                'asn': asn,
                'org_name': org_name,
                'postal': data.get('postal', ''),
                'timezone': data.get('timezone', ''),
                'is_bogon': data.get('bogon', False),
                'is_anycast': data.get('anycast', False),
                # Privacy detection (ücretli planda)
                'privacy': data.get('privacy', {}),
            }
        }

    except requests.exceptions.Timeout:
        return {'success': False, 'error': 'Bağlantı zaman aşımı'}
    except requests.exceptions.RequestException as e:
        return {'success': False, 'error': str(e)}


def _country_name(code):
    """Ülke kodu → tam isim (yaygın olanlar)"""
    countries = {
        'US': 'United States', 'GB': 'United Kingdom', 'DE': 'Germany',
        'FR': 'France', 'NL': 'Netherlands', 'RU': 'Russia',
        'CN': 'China', 'JP': 'Japan', 'KR': 'South Korea',
        'TR': 'Turkey', 'BR': 'Brazil', 'IN': 'India',
        'AU': 'Australia', 'CA': 'Canada', 'IT': 'Italy',
        'ES': 'Spain', 'SE': 'Sweden', 'NO': 'Norway',
        'FI': 'Finland', 'PL': 'Poland', 'UA': 'Ukraine',
        'RO': 'Romania', 'BG': 'Bulgaria', 'CZ': 'Czech Republic',
        'HU': 'Hungary', 'AT': 'Austria', 'CH': 'Switzerland',
        'BE': 'Belgium', 'IE': 'Ireland', 'SG': 'Singapore',
        'HK': 'Hong Kong', 'TW': 'Taiwan', 'TH': 'Thailand',
        'VN': 'Vietnam', 'ID': 'Indonesia', 'MY': 'Malaysia',
        'PH': 'Philippines', 'MX': 'Mexico', 'AR': 'Argentina',
        'CL': 'Chile', 'CO': 'Colombia', 'ZA': 'South Africa',
        'EG': 'Egypt', 'IL': 'Israel', 'AE': 'UAE',
        'SA': 'Saudi Arabia', 'IR': 'Iran', 'PK': 'Pakistan',
    }
    return countries.get(code, code)