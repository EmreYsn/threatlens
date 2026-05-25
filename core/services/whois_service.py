import whois
from datetime import datetime, timezone


def check_domain(domain):
    """WHOIS lookup - domain kayıt bilgileri"""
    try:
        w = whois.whois(domain)

        if not w or not w.domain_name:
            return {
                'success': True,
                'data': {
                    'domain': domain,
                    'found': False,
                    'message': 'WHOIS bilgisi bulunamadı',
                }
            }

        # Domain adını normalize et
        domain_name = w.domain_name
        if isinstance(domain_name, list):
            domain_name = domain_name[0]

        # Tarihleri parse et
        creation_date = _parse_date(w.creation_date)
        expiration_date = _parse_date(w.expiration_date)
        updated_date = _parse_date(w.updated_date)

        # Domain yaşını hesapla
        domain_age_days = None
        if creation_date:
            try:
                now = datetime.now(timezone.utc)
                if creation_date.tzinfo is None:
                    from datetime import timezone as tz
                    creation_date_aware = creation_date.replace(tzinfo=tz.utc)
                else:
                    creation_date_aware = creation_date
                domain_age_days = (now - creation_date_aware).days
            except Exception:
                pass

        # Registrar
        registrar = w.registrar or ''

        # Name servers
        name_servers = w.name_servers or []
        if isinstance(name_servers, str):
            name_servers = [name_servers]
        name_servers = [ns.lower() for ns in name_servers if ns]

        # Ülke
        country = w.country or ''

        # Org
        org = w.org or ''

        # Emails
        emails = w.emails or []
        if isinstance(emails, str):
            emails = [emails]

        # Status
        status = w.status or []
        if isinstance(status, str):
            status = [status]
        # Status'ları kısalt (uzun ICANN linklerini kaldır)
        clean_status = []
        for s in status:
            if ' ' in s:
                clean_status.append(s.split(' ')[0])
            else:
                clean_status.append(s)

        # DNSSEC
        dnssec = w.dnssec or ''
        if isinstance(dnssec, list):
            dnssec = dnssec[0] if dnssec else ''

        return {
            'success': True,
            'data': {
                'domain': domain_name,
                'found': True,
                'registrar': registrar,
                'creation_date': creation_date.strftime('%d/%m/%Y') if creation_date else None,
                'expiration_date': expiration_date.strftime('%d/%m/%Y') if expiration_date else None,
                'updated_date': updated_date.strftime('%d/%m/%Y') if updated_date else None,
                'domain_age_days': domain_age_days,
                'name_servers': name_servers[:6],
                'status': clean_status[:5],
                'country': country,
                'org': org,
                'emails': emails[:3],
                'dnssec': dnssec,
            }
        }

    except whois.parser.PywhoisError:
        return {
            'success': True,
            'data': {
                'domain': domain,
                'found': False,
                'message': 'Domain WHOIS kaydı bulunamadı',
            }
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}


def _parse_date(date_val):
    """WHOIS tarih değerini datetime'a çevir"""
    if not date_val:
        return None
    if isinstance(date_val, list):
        date_val = date_val[0]
    if isinstance(date_val, datetime):
        return date_val
    if isinstance(date_val, str):
        for fmt in ['%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d', '%d-%b-%Y']:
            try:
                return datetime.strptime(date_val, fmt)
            except ValueError:
                continue
    return None


def get_domain_age_risk(age_days):
    """Domain yaşına göre risk değerlendirmesi"""
    if age_days is None:
        return 'unknown', 'Bilinmiyor'
    if age_days < 30:
        return 'critical', 'Çok yeni (< 30 gün) - Yüksek risk'
    elif age_days < 90:
        return 'suspicious', 'Yeni (< 90 gün) - Orta risk'
    elif age_days < 365:
        return 'warning', '1 yıldan genç - Düşük risk'
    else:
        years = age_days // 365
        return 'safe', f'{years} yıllık - Güvenilir'