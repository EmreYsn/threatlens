"""
IOC (Indicator of Compromise) tipi algılama modülü.
Kullanıcının girdiği değerin IP, domain, URL, hash veya email olduğunu tespit eder.
"""

import re
import ipaddress


def detect_ioc_type(value: str) -> str | None:
    """
    Verilen string'in IOC tipini algılar.
    Returns: 'ip', 'domain', 'url', 'hash', 'email' veya None
    """
    value = value.strip()

    # Email kontrolü
    if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
        return 'email'

    # URL kontrolü (http/https ile başlayan)
    if re.match(r'^https?://', value, re.IGNORECASE):
        return 'url'

    # IP adresi kontrolü (IPv4 ve IPv6)
    try:
        ipaddress.ip_address(value)
        return 'ip'
    except ValueError:
        pass

    # Hash kontrolü (MD5, SHA1, SHA256)
    if re.match(r'^[a-fA-F0-9]{32}$', value):  # MD5
        return 'hash'
    if re.match(r'^[a-fA-F0-9]{40}$', value):  # SHA1
        return 'hash'
    if re.match(r'^[a-fA-F0-9]{64}$', value):  # SHA256
        return 'hash'

    # Domain kontrolü (en son kontrol et)
    if re.match(r'^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', value):
        return 'domain'

    return None


def get_ioc_type_display(ioc_type: str) -> str:
    """IOC tipinin Türkçe karşılığı"""
    mapping = {
        'ip': 'IP Adresi',
        'domain': 'Domain',
        'url': 'URL',
        'hash': 'Dosya Hash',
        'email': 'Email',
    }
    return mapping.get(ioc_type, 'Bilinmiyor')


def validate_ioc(value: str, ioc_type: str) -> tuple[bool, str]:
    """
    IOC değerini doğrula.
    Returns: (geçerli_mi, hata_mesajı)
    """
    value = value.strip()

    if not value:
        return False, "Değer boş olamaz."

    if len(value) > 2048:
        return False, "Değer çok uzun (max 2048 karakter)."

    if ioc_type == 'ip':
        try:
            ip = ipaddress.ip_address(value)
            if ip.is_private:
                return False, "Özel (private) IP adresleri sorgulanamaz."
            if ip.is_loopback:
                return False, "Loopback adresleri sorgulanamaz."
            return True, ""
        except ValueError:
            return False, "Geçersiz IP adresi."

    if ioc_type == 'hash':
        if not re.match(r'^[a-fA-F0-9]{32,64}$', value):
            return False, "Geçersiz hash değeri. MD5 (32), SHA1 (40) veya SHA256 (64) karakter olmalı."
        return True, ""

    if ioc_type == 'email':
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            return False, "Geçersiz email adresi."
        return True, ""

    if ioc_type == 'url':
        if not re.match(r'^https?://', value, re.IGNORECASE):
            return False, "URL http:// veya https:// ile başlamalı."
        return True, ""

    if ioc_type == 'domain':
        if not re.match(r'^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', value):
            return False, "Geçersiz domain adı."
        return True, ""

    return False, "Bilinmeyen IOC tipi."
