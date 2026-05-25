import requests
from django.conf import settings


def check_ip(ip_address):
    """Shodan IP lookup - açık portlar, servisler, güvenlik açıkları"""
    api_key = getattr(settings, 'SHODAN_API_KEY', '')
    if not api_key:
        return {'success': False, 'error': 'Shodan API key tanımlı değil'}

    try:
        url = f'https://api.shodan.io/shodan/host/{ip_address}'
        params = {'key': api_key}
        response = requests.get(url, params=params, timeout=15)

        if response.status_code == 401:
            return {'success': False, 'error': 'Geçersiz API key'}
        if response.status_code == 402:
            return {'success': False, 'error': 'Shodan kredi yetersiz'}
        if response.status_code == 404:
            return {
                'success': True,
                'data': {
                    'ip': ip_address,
                    'found': False,
                    'ports': [],
                    'services': [],
                    'vulns': [],
                    'message': 'Bu IP Shodan veritabanında bulunamadı',
                }
            }
        if response.status_code == 429:
            return {'success': False, 'error': 'Rate limit aşıldı'}
        if response.status_code != 200:
            return {'success': False, 'error': f'HTTP {response.status_code}'}

        data = response.json()

        # Açık portlar
        ports = data.get('ports', [])

        # Servisleri topla
        services = []
        for item in data.get('data', []):
            service = {
                'port': item.get('port', 0),
                'transport': item.get('transport', 'tcp'),
                'product': item.get('product', ''),
                'version': item.get('version', ''),
                'banner': (item.get('data', '')[:200] if item.get('data') else ''),
                'module': item.get('_shodan', {}).get('module', ''),
            }
            services.append(service)

        # Güvenlik açıkları
        vulns = list(data.get('vulns', {}).keys()) if data.get('vulns') else []

        # OS tespiti
        os_name = data.get('os', '')

        return {
            'success': True,
            'data': {
                'ip': ip_address,
                'found': True,
                'ports': sorted(ports),
                'services': services[:20],
                'vulns': vulns[:15],
                'os': os_name,
                'hostnames': data.get('hostnames', []),
                'domains': data.get('domains', []),
                'org': data.get('org', ''),
                'isp': data.get('isp', ''),
                'asn': data.get('asn', ''),
                'city': data.get('city', ''),
                'country_name': data.get('country_name', ''),
                'country_code': data.get('country_code', ''),
                'latitude': data.get('latitude', None),
                'longitude': data.get('longitude', None),
                'last_update': data.get('last_update', ''),
                'port_count': len(ports),
                'vuln_count': len(vulns),
            }
        }

    except requests.exceptions.Timeout:
        return {'success': False, 'error': 'Bağlantı zaman aşımı'}
    except requests.exceptions.RequestException as e:
        return {'success': False, 'error': str(e)}