import time
import requests
from functools import wraps


def api_call_with_retry(max_retries=2, timeout=15, retry_delay=2):
    """API çağrıları için retry decorator"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_error = None
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except requests.exceptions.Timeout:
                    last_error = 'Bağlantı zaman aşımı'
                    if attempt < max_retries:
                        time.sleep(retry_delay)
                except requests.exceptions.ConnectionError:
                    last_error = 'Bağlantı hatası'
                    if attempt < max_retries:
                        time.sleep(retry_delay)
                except requests.exceptions.RequestException as e:
                    last_error = str(e)
                    break  # Diğer hatalar için retry yapma

            return {'success': False, 'error': f'{last_error} ({max_retries + 1} deneme)'}
        return wrapper
    return decorator


def safe_api_request(url, headers=None, params=None, method='GET', timeout=15, data=None):
    """Güvenli API isteği - ortak hata yönetimi"""
    try:
        if method == 'GET':
            response = requests.get(url, headers=headers, params=params, timeout=timeout)
        elif method == 'POST':
            response = requests.post(url, headers=headers, data=data, timeout=timeout)
        else:
            return None, 'Geçersiz HTTP metodu'

        if response.status_code == 401:
            return None, 'Geçersiz API key'
        if response.status_code == 403:
            return None, 'Erişim engellendi'
        if response.status_code == 429:
            return None, 'Rate limit aşıldı, lütfen bekleyin'
        if response.status_code == 404:
            return response, 'not_found'
        if response.status_code != 200:
            return None, f'HTTP {response.status_code}'

        return response, None

    except requests.exceptions.Timeout:
        return None, 'Bağlantı zaman aşımı (15s)'
    except requests.exceptions.ConnectionError:
        return None, 'Sunucuya bağlanılamadı'
    except requests.exceptions.RequestException as e:
        return None, str(e)