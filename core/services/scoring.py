def calculate_threat_score(ioc_type, api_results):
    """
    Çoklu kaynak ağırlıklı tehdit skoru hesaplama.

    Kaynaklar ve ağırlıkları (IP için):
        AbuseIPDB  : %35
        VirusTotal : %40
        ipinfo     : %10
        (gelecekte: Shodan %10, GreyNoise %5)

    Domain/URL/Hash için VirusTotal ağırlığı daha yüksek.
    """
    scores = []
    breakdown = []

    # ──────────── AbuseIPDB (IP only) ────────────
    if ioc_type == 'ip' and 'abuseipdb' in api_results:
        result = api_results['abuseipdb']
        if result.get('success'):
            data = result['data']
            abuse_score = data.get('abuse_confidence_score', 0)
            total_reports = data.get('total_reports', 0)
            is_tor = data.get('is_tor', False)
            is_whitelisted = data.get('is_whitelisted', False)

            # Skor hesabı
            raw = abuse_score
            if total_reports > 100:
                raw = min(100, raw + 10)
            elif total_reports > 50:
                raw = min(100, raw + 5)
            if is_tor:
                raw = min(100, raw + 15)
            if is_whitelisted:
                raw = max(0, raw - 30)

            weight = 0.35
            scores.append((raw, weight))
            breakdown.append({
                'source': 'AbuseIPDB',
                'score': raw,
                'weight': int(weight * 100),
                'details': (
                    f'Güven skoru: {abuse_score}/100, '
                    f'Toplam rapor: {total_reports}, '
                    f'Tor: {"Evet" if is_tor else "Hayır"}'
                ),
            })

    # ──────────── VirusTotal ────────────
    if 'virustotal' in api_results:
        result = api_results['virustotal']
        if result.get('success'):
            data = result['data']
            malicious = data.get('malicious', 0)
            suspicious = data.get('suspicious', 0)
            total = data.get('total_vendors', 0)

            # Detection ratio'dan skor hesapla
            if total > 0:
                detection_ratio = (malicious + suspicious * 0.5) / total
                raw = min(100, int(detection_ratio * 100 * 2.5))
                # 2.5x multiplier: %40 detection = 100 skor
            else:
                raw = 0

            # Reputation bonus/penalty
            reputation = data.get('reputation', 0)
            if reputation < -5:
                raw = min(100, raw + 10)
            elif reputation > 5:
                raw = max(0, raw - 5)

            # Hash bulunamadıysa
            if data.get('found') is False:
                raw = 15  # bilinmiyor = hafif şüpheli

            # Scan yeni gönderildiyse
            if data.get('scan_submitted'):
                raw = 20  # henüz sonuç yok

            # IOC tipine göre ağırlık
            if ioc_type == 'ip':
                weight = 0.40
            elif ioc_type in ('domain', 'url'):
                weight = 0.50
            elif ioc_type == 'hash':
                weight = 0.65
            else:
                weight = 0.50

            scores.append((raw, weight))
            breakdown.append({
                'source': 'VirusTotal',
                'score': raw,
                'weight': int(weight * 100),
                'details': (
                    f'Tespit: {malicious} kötü, {suspicious} şüpheli / '
                    f'{total} motor'
                ),
            })

    # ──────────── AlienVault OTX ────────────
    if 'alienvault' in api_results:
        result = api_results['alienvault']
        if result.get('success'):
            data = result['data']
            pulse_count = data.get('pulse_count', 0)
            threat_score_otx = data.get('threat_score', 0)

            # Pulse sayısına göre skor
            if pulse_count == 0:
                raw = 0
            elif pulse_count <= 3:
                raw = 25
            elif pulse_count <= 10:
                raw = 50
            elif pulse_count <= 30:
                raw = 70
            else:
                raw = 90

            # OTX kendi threat score'u varsa blend et
            if threat_score_otx > 0:
                raw = max(raw, min(100, threat_score_otx * 25))

            # Aktivite varsa bonus
            activities = data.get('activities', [])
            if activities:
                raw = min(100, raw + 10)

            # IOC tipine göre ağırlık
            if ioc_type == 'ip':
                weight = 0.15
            elif ioc_type in ('domain', 'url'):
                weight = 0.20
            elif ioc_type == 'hash':
                weight = 0.20
            else:
                weight = 0.15

            scores.append((raw, weight))

            details = f'Pulse sayısı: {pulse_count}'
            if activities:
                details += f' | Aktivite: {", ".join(activities[:3])}'
            pulse_names = data.get('pulse_names', [])
            if pulse_names:
                details += f' | Örnek: {pulse_names[0][:50]}'

            breakdown.append({
                'source': 'AlienVault OTX',
                'score': raw,
                'weight': int(weight * 100),
                'details': details,
            })

    # ──────────── Shodan ────────────
    if ioc_type == 'ip' and 'shodan' in api_results:
        result = api_results['shodan']
        if result.get('success'):
            data = result['data']

            if data.get('found') is False:
                raw = 0
            else:
                raw = 0
                port_count = data.get('port_count', 0)
                vuln_count = data.get('vuln_count', 0)
                ports = data.get('ports', [])

                # Açık port sayısına göre
                if port_count > 20:
                    raw = 40
                elif port_count > 10:
                    raw = 25
                elif port_count > 5:
                    raw = 15

                # Tehlikeli portlar
                dangerous_ports = {23, 445, 3389, 5900, 1433, 3306, 6379, 27017, 9200}
                open_dangerous = set(ports) & dangerous_ports
                if open_dangerous:
                    raw = min(100, raw + len(open_dangerous) * 10)

                # Güvenlik açıkları (CVE)
                if vuln_count > 10:
                    raw = min(100, raw + 40)
                elif vuln_count > 5:
                    raw = min(100, raw + 25)
                elif vuln_count > 0:
                    raw = min(100, raw + 15)

            weight = 0.15
            scores.append((raw, weight))

            # Detay metni
            details_parts = []
            if data.get('found') is False:
                details_parts.append('Shodan\'da bulunamadı')
            else:
                details_parts.append(f'{data.get("port_count", 0)} açık port')
                if data.get('vuln_count', 0) > 0:
                    details_parts.append(f'{data["vuln_count"]} güvenlik açığı')
                if data.get('os'):
                    details_parts.append(f'OS: {data["os"]}')

            breakdown.append({
                'source': 'Shodan',
                'score': raw,
                'weight': int(weight * 100),
                'details': ' | '.join(details_parts),
            })

    # ──────────── WHOIS ────────────
    if ioc_type in ('domain', 'url') and 'whois' in api_results:
        result = api_results['whois']
        if result.get('success'):
            data = result['data']

            if data.get('found') is False:
                raw = 30  # WHOIS bilgisi yok = şüpheli
            else:
                raw = 0
                age_days = data.get('domain_age_days')

                # Domain yaşına göre skor
                if age_days is not None:
                    if age_days < 30:
                        raw = 80  # Çok yeni domain = yüksek risk
                    elif age_days < 90:
                        raw = 50
                    elif age_days < 365:
                        raw = 20
                    else:
                        raw = 0  # Eski domain = güvenli

                # Privacy/proxy registrar kontrolü
                registrar = data.get('registrar', '').lower()
                privacy_keywords = ['privacy', 'proxy', 'whoisguard', 'domains by proxy', 'redacted']
                if any(kw in registrar for kw in privacy_keywords):
                    raw = min(100, raw + 10)

            weight = 0.15
            scores.append((raw, weight))

            details_parts = []
            if data.get('found') is False:
                details_parts.append('WHOIS bilgisi bulunamadı')
            else:
                if data.get('domain_age_days') is not None:
                    years = data['domain_age_days'] // 365
                    days = data['domain_age_days'] % 365
                    if years > 0:
                        details_parts.append(f'Yaş: {years} yıl {days} gün')
                    else:
                        details_parts.append(f'Yaş: {data["domain_age_days"]} gün')
                if data.get('registrar'):
                    details_parts.append(f'Registrar: {data["registrar"][:40]}')

            breakdown.append({
                'source': 'WHOIS',
                'score': raw,
                'weight': int(weight * 100),
                'details': ' | '.join(details_parts) if details_parts else 'Veri yok',
            })

    # ──────────── ipinfo.io (IP only, düşük ağırlık) ────────────
    if ioc_type == 'ip' and 'ipinfo' in api_results:
        result = api_results['ipinfo']
        if result.get('success'):
            data = result['data']
            raw = 0

            # Bogon IP → şüpheli
            if data.get('is_bogon'):
                raw = 40

            # Privacy tespiti (VPN, proxy, tor, relay, hosting)
            privacy = data.get('privacy', {})
            if privacy:
                if privacy.get('vpn'):
                    raw = max(raw, 25)
                if privacy.get('proxy'):
                    raw = max(raw, 35)
                if privacy.get('tor'):
                    raw = max(raw, 50)
                if privacy.get('hosting'):
                    raw = max(raw, 20)

            weight = 0.10
            scores.append((raw, weight))

            privacy_flags = []
            if data.get('is_bogon'):
                privacy_flags.append('Bogon')
            if privacy.get('vpn'):
                privacy_flags.append('VPN')
            if privacy.get('proxy'):
                privacy_flags.append('Proxy')
            if privacy.get('tor'):
                privacy_flags.append('Tor')
            if privacy.get('hosting'):
                privacy_flags.append('Hosting')

            location = ', '.join(filter(None, [
                data.get('city', ''), data.get('country_name', '')
            ]))

            breakdown.append({
                'source': 'ipinfo.io',
                'score': raw,
                'weight': int(weight * 100),
                'details': (
                    f'Konum: {location or "Bilinmiyor"}'
                    + (f' | Bayrak: {", ".join(privacy_flags)}' if privacy_flags else '')
                ),
            })

    # ──────────── TOPLAM SKOR ────────────
    if not scores:
        return 0, breakdown

    # Ağırlıklı ortalama
    total_weight = sum(w for _, w in scores)
    if total_weight > 0:
        weighted_sum = sum(s * w for s, w in scores)
        final_score = int(weighted_sum / total_weight)
    else:
        final_score = 0

    final_score = max(0, min(100, final_score))

    return final_score, breakdown


def get_severity(score):
    """Skor → severity string"""
    if score <= 30:
        return 'safe'
    elif score <= 60:
        return 'suspicious'
    else:
        return 'malicious'