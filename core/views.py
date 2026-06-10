import json
import time
from datetime import timedelta
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.db.models import Count
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
from .services.shodan_service import check_ip as shodan_check

from .models import IOC, Note, QueryLog, Tag
from .services.ioc_utils import detect_ioc_type, validate_ioc
from .services.abuseipdb import check_ip as abuseipdb_check
from .services.scoring import calculate_threat_score, get_severity
from .services.virustotal import check_ip as vt_check_ip, check_domain as vt_check_domain, check_url as vt_check_url, check_hash as vt_check_hash
from .services.ipinfo import check_ip as ipinfo_check
from .services.alienvault import check_ip as otx_check_ip, check_domain as otx_check_domain, check_hash as otx_check_hash
from .services.pdf_report import generate_ioc_report
from .services.whois_service import check_domain as whois_check

import csv
from io import TextIOWrapper

from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from .forms import IOCSearchForm, NoteForm, CSVUploadForm, RegisterForm

def index(request):
    """Ana sayfa - arama formu ve son sorgular"""
    form = IOCSearchForm()
    recent_queries = IOC.objects.all()[:10]
    total_iocs = IOC.objects.count()

    # İstatistikler
    stats = {
        'total': total_iocs,
        'malicious': IOC.objects.filter(severity='malicious').count(),
        'suspicious': IOC.objects.filter(severity='suspicious').count(),
        'safe': IOC.objects.filter(severity='safe').count(),
    }

    return render(request, 'core/index.html', {
        'form': form,
        'recent_queries': recent_queries,
        'stats': stats,
    })


def search(request):
    """IOC sorgulama - POST ile gelir, sonuç sayfasına yönlendirir"""
    if request.method != 'POST':
        return redirect('index')

    form = IOCSearchForm(request.POST)
    if not form.is_valid():
        messages.error(request, 'Geçersiz giriş.')
        return redirect('index')

    query = form.cleaned_data['query'].strip()

    # IOC tipini algıla
    ioc_type = detect_ioc_type(query)
    if not ioc_type:
        messages.error(request, f'"{query}" tanınamadı. Lütfen geçerli bir IP, domain, URL, hash veya email girin.')
        return redirect('index')

    # IOC'yi doğrula
    is_valid, error_msg = validate_ioc(query, ioc_type)
    if not is_valid:
        messages.error(request, error_msg)
        return redirect('index')

    # Kullanıcı giriş yaptıysa kendi IOC'sini ara, yapmadıysa genel ara
    if request.user.is_authenticated:
        ioc, created = IOC.objects.get_or_create(
            value=query,
            ioc_type=ioc_type,
            defaults={'user': request.user}
        )
    else:
        ioc, created = IOC.objects.get_or_create(
            value=query,
            ioc_type=ioc_type,
        )

    if not created:
        ioc.query_count += 1

        # Cache: Son 1 saat içinde sorgulandıysa API'ye gitme
        from django.utils import timezone
        from datetime import timedelta
        cache_duration = timedelta(hours=1)
        if ioc.last_queried and (timezone.now() - ioc.last_queried) < cache_duration:
            ioc.save()
            QueryLog.objects.create(
                ioc=ioc,
                sources_queried=['cache'],
                response_time_ms=0,
            )
            messages.info(request, f'Cache\'den yüklendi (son sorgu: {ioc.last_queried.strftime("%H:%M")}). Yeni sorgu için 1 saat bekleyin veya "Yeniden Sorgula" butonunu kullanın.')
            return redirect('result', ioc_id=ioc.id)

    # API sorgularını çalıştır
    start_time = time.time()
    api_results = {}
    sources_queried = []

    if ioc_type == 'ip':
        # AbuseIPDB
        abuseipdb_result = abuseipdb_check(query)
        api_results['abuseipdb'] = abuseipdb_result
        sources_queried.append('abuseipdb')
        if abuseipdb_result['success']:
            data = abuseipdb_result['data']
            ioc.abuseipdb_data = data
            ioc.country_code = data.get('country_code', '')
            ioc.country = data.get('country_name', '')
            ioc.isp = data.get('isp', '')

        # VirusTotal IP
        vt_result = vt_check_ip(query)
        api_results['virustotal'] = vt_result
        sources_queried.append('virustotal')
        if vt_result['success']:
            ioc.virustotal_data = vt_result['data']

        # AlienVault OTX
        otx_result = otx_check_ip(query)
        api_results['alienvault'] = otx_result
        sources_queried.append('alienvault')
        if otx_result['success']:
            ioc.alienvault_data = otx_result['data']

        # Shodan
        shodan_result = shodan_check(query)
        api_results['shodan'] = shodan_result
        sources_queried.append('shodan')
        if shodan_result['success']:
            ioc.shodan_data = shodan_result['data']

        # ipinfo.io
        ipinfo_result = ipinfo_check(query)
        api_results['ipinfo'] = ipinfo_result
        sources_queried.append('ipinfo')
        if ipinfo_result['success']:
            ioc.ipinfo_data = ipinfo_result['data']
            # ipinfo'dan gelen konum bilgisini doldur (AbuseIPDB boşsa)
            if not ioc.country_code and ipinfo_result['data'].get('country'):
                ioc.country_code = ipinfo_result['data']['country']
                ioc.country = ipinfo_result['data'].get('country_name', '')
            if not ioc.asn and ipinfo_result['data'].get('asn'):
                ioc.asn = ipinfo_result['data']['asn']

    elif ioc_type == 'domain':
        # VirusTotal domain
        vt_result = vt_check_domain(query)
        api_results['virustotal'] = vt_result
        sources_queried.append('virustotal')
        if vt_result['success']:
            ioc.virustotal_data = vt_result['data']

        # AlienVault OTX domain
        otx_result = otx_check_domain(query)
        api_results['alienvault'] = otx_result
        sources_queried.append('alienvault')
        if otx_result['success']:
            ioc.alienvault_data = otx_result['data']
        
        # WHOIS
        whois_result = whois_check(query)
        api_results['whois'] = whois_result
        sources_queried.append('whois')
        if whois_result['success']:
            ioc.whois_data = whois_result['data']

    elif ioc_type == 'url':
        # VirusTotal URL
        vt_result = vt_check_url(query)
        api_results['virustotal'] = vt_result
        sources_queried.append('virustotal')
        if vt_result['success']:
            ioc.virustotal_data = vt_result['data']
        
        # WHOIS (URL'den domain çıkar)
        from urllib.parse import urlparse
        parsed = urlparse(query)
        domain_for_whois = parsed.netloc or parsed.path.split('/')[0]
        if domain_for_whois:
            whois_result = whois_check(domain_for_whois)
            api_results['whois'] = whois_result
            sources_queried.append('whois')
            if whois_result['success']:
                ioc.whois_data = whois_result['data']

    elif ioc_type == 'hash':
        # VirusTotal hash
        vt_result = vt_check_hash(query)
        api_results['virustotal'] = vt_result
        sources_queried.append('virustotal')
        if vt_result['success']:
            ioc.virustotal_data = vt_result['data']

        # AlienVault OTX hash
        otx_result = otx_check_hash(query)
        api_results['alienvault'] = otx_result
        sources_queried.append('alienvault')
        if otx_result['success']:
            ioc.alienvault_data = otx_result['data']

    elif ioc_type == 'email':
        # Email'den domain çıkar
        email_domain = query.split('@')[1] if '@' in query else None

        if email_domain:
            # VirusTotal domain kontrolü
            vt_result = vt_check_domain(email_domain)
            api_results['virustotal'] = vt_result
            sources_queried.append('virustotal')
            if vt_result['success']:
                ioc.virustotal_data = vt_result['data']

            # AlienVault OTX domain kontrolü
            otx_result = otx_check_domain(email_domain)
            api_results['alienvault'] = otx_result
            sources_queried.append('alienvault')
            if otx_result['success']:
                ioc.alienvault_data = otx_result['data']

            # WHOIS
            whois_result = whois_check(email_domain)
            api_results['whois'] = whois_result
            sources_queried.append('whois')
            if whois_result['success']:
                ioc.whois_data = whois_result['data']

    # API'lerden veri geldi mi kontrol et
    any_success = any(
        r.get('success') for r in api_results.values()
    )

    if not any_success and created:
        # Hiçbir API'den veri gelmedi ve yeni IOC ise, sil
        ioc.delete()
        messages.error(request, f'"{query}" için hiçbir kaynaktan veri alınamadı. Lütfen geçerli bir IOC girin.')
        return redirect('index')

    # Tehdit skoru hesapla
    score, breakdown = calculate_threat_score(ioc_type, api_results)
    ioc.threat_score = score
    ioc.severity = get_severity(score)
    ioc.save()

    # Sorgu logunu kaydet
    elapsed_ms = int((time.time() - start_time) * 1000)
    QueryLog.objects.create(
        ioc=ioc,
        sources_queried=sources_queried,
        response_time_ms=elapsed_ms,
    )

    messages.success(request, f'Sorgu tamamlandı ({elapsed_ms}ms) — {len(sources_queried)} kaynak')

    return redirect('result', ioc_id=ioc.id)

def rescan(request, ioc_id):
    """IOC'yi yeniden sorgula (cache'i atla)"""
    ioc = get_object_or_404(IOC, id=ioc_id)
    ioc.query_count += 1

    start_time = time.time()
    api_results = {}
    sources_queried = []

    if ioc.ioc_type == 'ip':
        abuseipdb_result = abuseipdb_check(ioc.value)
        api_results['abuseipdb'] = abuseipdb_result
        sources_queried.append('abuseipdb')
        if abuseipdb_result['success']:
            data = abuseipdb_result['data']
            ioc.abuseipdb_data = data
            ioc.country_code = data.get('country_code', '')
            ioc.country = data.get('country_name', '')
            ioc.isp = data.get('isp', '')

        vt_result = vt_check_ip(ioc.value)
        api_results['virustotal'] = vt_result
        sources_queried.append('virustotal')
        if vt_result['success']:
            ioc.virustotal_data = vt_result['data']

        otx_result = otx_check_ip(ioc.value)
        api_results['alienvault'] = otx_result
        sources_queried.append('alienvault')
        if otx_result['success']:
            ioc.alienvault_data = otx_result['data']

        shodan_result = shodan_check(ioc.value)
        api_results['shodan'] = shodan_result
        sources_queried.append('shodan')
        if shodan_result['success']:
            ioc.shodan_data = shodan_result['data']

        ipinfo_result = ipinfo_check(ioc.value)
        api_results['ipinfo'] = ipinfo_result
        sources_queried.append('ipinfo')
        if ipinfo_result['success']:
            ioc.ipinfo_data = ipinfo_result['data']

    elif ioc.ioc_type == 'domain':
        vt_result = vt_check_domain(ioc.value)
        api_results['virustotal'] = vt_result
        sources_queried.append('virustotal')
        if vt_result['success']:
            ioc.virustotal_data = vt_result['data']

        otx_result = otx_check_domain(ioc.value)
        api_results['alienvault'] = otx_result
        sources_queried.append('alienvault')
        if otx_result['success']:
            ioc.alienvault_data = otx_result['data']

        whois_result = whois_check(ioc.value)
        api_results['whois'] = whois_result
        sources_queried.append('whois')
        if whois_result['success']:
            ioc.whois_data = whois_result['data']

    elif ioc.ioc_type == 'url':
        vt_result = vt_check_url(ioc.value)
        api_results['virustotal'] = vt_result
        sources_queried.append('virustotal')
        if vt_result['success']:
            ioc.virustotal_data = vt_result['data']

    elif ioc.ioc_type == 'hash':
        vt_result = vt_check_hash(ioc.value)
        api_results['virustotal'] = vt_result
        sources_queried.append('virustotal')
        if vt_result['success']:
            ioc.virustotal_data = vt_result['data']

        otx_result = otx_check_hash(ioc.value)
        api_results['alienvault'] = otx_result
        sources_queried.append('alienvault')
        if otx_result['success']:
            ioc.alienvault_data = otx_result['data']

    elif ioc.ioc_type == 'email':
        email_domain = ioc.value.split('@')[1] if '@' in ioc.value else None
        if email_domain:
            vt_result = vt_check_domain(email_domain)
            api_results['virustotal'] = vt_result
            sources_queried.append('virustotal')
            if vt_result['success']:
                ioc.virustotal_data = vt_result['data']

            otx_result = otx_check_domain(email_domain)
            api_results['alienvault'] = otx_result
            sources_queried.append('alienvault')
            if otx_result['success']:
                ioc.alienvault_data = otx_result['data']

            whois_result = whois_check(email_domain)
            api_results['whois'] = whois_result
            sources_queried.append('whois')
            if whois_result['success']:
                ioc.whois_data = whois_result['data']

    score, _ = calculate_threat_score(ioc.ioc_type, api_results)
    ioc.threat_score = score
    ioc.severity = get_severity(score)
    ioc.save()

    elapsed_ms = int((time.time() - start_time) * 1000)
    QueryLog.objects.create(
        ioc=ioc,
        sources_queried=sources_queried,
        response_time_ms=elapsed_ms,
    )

    messages.success(request, f'Yeniden sorgulandı ({elapsed_ms}ms)')
    return redirect('result', ioc_id=ioc.id)

def result(request, ioc_id):
    """IOC sonuç sayfası"""
    ioc = get_object_or_404(IOC, id=ioc_id)
    note_form = NoteForm()
    notes = ioc.notes.all()
    tags = Tag.objects.all()
    query_logs = ioc.query_logs.all()[:5]

    api_results = {}
    if ioc.abuseipdb_data:
        api_results['abuseipdb'] = {'success': True, 'data': ioc.abuseipdb_data}
    if ioc.virustotal_data:
        api_results['virustotal'] = {'success': True, 'data': ioc.virustotal_data}
    if ioc.ipinfo_data:
        api_results['ipinfo'] = {'success': True, 'data': ioc.ipinfo_data}
    if ioc.alienvault_data:
        api_results['alienvault'] = {'success': True, 'data': ioc.alienvault_data}
    if ioc.shodan_data:
        api_results['shodan'] = {'success': True, 'data': ioc.shodan_data}
    if ioc.whois_data:
        api_results['whois'] = {'success': True, 'data': ioc.whois_data}

    _, breakdown = calculate_threat_score(ioc.ioc_type, api_results)

    return render(request, 'core/result.html', {
        'ioc': ioc,
        'note_form': note_form,
        'notes': notes,
        'tags': tags,
        'breakdown': breakdown,
        'query_logs': query_logs,
    })


def add_note(request, ioc_id):
    """IOC'ye not ekle"""
    if request.method != 'POST':
        return redirect('result', ioc_id=ioc_id)

    ioc = get_object_or_404(IOC, id=ioc_id)
    form = NoteForm(request.POST)

    if form.is_valid():
        Note.objects.create(
            ioc=ioc,
            content=form.cleaned_data['content'],
        )
        messages.success(request, 'Not eklendi.')

    return redirect('result', ioc_id=ioc.id)


def toggle_tag(request, ioc_id, tag_id):
    """IOC'ye etiket ekle/çıkar"""
    ioc = get_object_or_404(IOC, id=ioc_id)
    tag = get_object_or_404(Tag, id=tag_id)

    if tag in ioc.tags.all():
        ioc.tags.remove(tag)
    else:
        ioc.tags.add(tag)

    return redirect('result', ioc_id=ioc.id)


def history(request):
    """Sorgu geçmişi — pagination ile"""
    from django.core.paginator import Paginator

    iocs = IOC.objects.all()

    # Filtreleme
    ioc_type = request.GET.get('type')
    severity = request.GET.get('severity')
    search_q = request.GET.get('q')

    if ioc_type:
        iocs = iocs.filter(ioc_type=ioc_type)
    if severity:
        iocs = iocs.filter(severity=severity)
    if search_q:
        iocs = iocs.filter(value__icontains=search_q)

    # Pagination
    paginator = Paginator(iocs, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'core/history.html', {
        'iocs': page_obj,
        'page_obj': page_obj,
        'current_type': ioc_type,
        'current_severity': severity,
        'search_q': search_q or '',
    })


def dashboard(request):
    """Dashboard - istatistikler ve grafikler"""
    total_iocs = IOC.objects.count()
    critical_count = IOC.objects.filter(severity='malicious').count()
    suspicious_count = IOC.objects.filter(severity='suspicious').count()
    safe_count = IOC.objects.filter(severity='safe').count()
    total_queries = QueryLog.objects.count()

    # IOC tip dağılımı
    type_qs = IOC.objects.values('ioc_type').annotate(count=Count('id'))
    type_labels = {'ip': 'IP', 'domain': 'Domain', 'url': 'URL', 'hash': 'Hash', 'email': 'Email'}
    type_stats = {type_labels.get(t['ioc_type'], t['ioc_type']): t['count'] for t in type_qs}

    # Severity dağılımı
    severity_stats = {}
    if safe_count: severity_stats['Güvenli'] = safe_count
    if suspicious_count: severity_stats['Şüpheli'] = suspicious_count
    if critical_count: severity_stats['Tehlikeli'] = critical_count

    # Son 7 gün sorgu trendi
    today = timezone.now().date()
    trend_labels = []
    trend_values = []
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        count = QueryLog.objects.filter(
            queried_at__date=day
        ).count()
        trend_labels.append(day.strftime('%d/%m'))
        trend_values.append(count)

    trend_data = {'labels': trend_labels, 'values': trend_values}

    # En tehlikeli IOC'ler
    top_threats = IOC.objects.filter(severity='malicious').order_by('-threat_score')[:10]

    # Son sorgular
    recent_iocs = IOC.objects.all()[:10]

    # Ülke dağılımı
    country_stats = (
        IOC.objects.exclude(country='').exclude(country__isnull=True)
        .values('country', 'country_code')
        .annotate(count=Count('id'))
        .order_by('-count')[:8]
    )

    # Harita verisi (koordinatlı IOC'ler)
    map_iocs = IOC.objects.exclude(
        ipinfo_data={},
    ).exclude(
        ipinfo_data__isnull=True,
    )

    map_data = []
    for m_ioc in map_iocs:
        ipinfo = m_ioc.ipinfo_data or {}
        lat = ipinfo.get('latitude')
        lon = ipinfo.get('longitude')
        if lat and lon:
            map_data.append({
                'value': m_ioc.value,
                'score': m_ioc.threat_score,
                'city': ipinfo.get('city', ''),
                'country': ipinfo.get('country_name', ''),
                'lat': lat,
                'lon': lon,
            })

    # Son 30 gün detaylı trend
    trend_30_labels = []
    trend_30_safe = []
    trend_30_suspicious = []
    trend_30_malicious = []
    trend_30_total = []

    for i in range(29, -1, -1):
        day = today - timedelta(days=i)
        day_logs = QueryLog.objects.filter(queried_at__date=day)
        day_iocs = IOC.objects.filter(query_logs__queried_at__date=day)

        trend_30_labels.append(day.strftime('%d/%m'))
        trend_30_total.append(day_logs.count())
        trend_30_safe.append(day_iocs.filter(severity='safe').count())
        trend_30_suspicious.append(day_iocs.filter(severity='suspicious').count())
        trend_30_malicious.append(day_iocs.filter(severity='malicious').count())

    trend_30_data = {
        'labels': trend_30_labels,
        'total': trend_30_total,
        'safe': trend_30_safe,
        'suspicious': trend_30_suspicious,
        'malicious': trend_30_malicious,
    }

    return render(request, 'core/dashboard.html', {
        'total_iocs': total_iocs,
        'critical_count': critical_count,
        'suspicious_count': suspicious_count,
        'safe_count': safe_count,
        'total_queries': total_queries,
        'type_stats': json.dumps(type_stats),
        'severity_stats': json.dumps(severity_stats),
        'trend_data': json.dumps(trend_data),
        'top_threats': top_threats,
        'recent_iocs': recent_iocs,
        'country_stats': country_stats,
        'map_data': json.dumps(map_data),
        'trend_30_data': json.dumps(trend_30_data),
    })

def export_pdf(request, ioc_id):
    """IOC raporu PDF olarak indir"""
    ioc = get_object_or_404(IOC, id=ioc_id)

    # Breakdown hesapla
    api_results = {}
    if ioc.abuseipdb_data:
        api_results['abuseipdb'] = {'success': True, 'data': ioc.abuseipdb_data}
    if ioc.virustotal_data:
        api_results['virustotal'] = {'success': True, 'data': ioc.virustotal_data}
    if ioc.ipinfo_data:
        api_results['ipinfo'] = {'success': True, 'data': ioc.ipinfo_data}
    if ioc.alienvault_data:
        api_results['alienvault'] = {'success': True, 'data': ioc.alienvault_data}
    if ioc.shodan_data:
        api_results['shodan'] = {'success': True, 'data': ioc.shodan_data}
    if ioc.whois_data:
        api_results['whois'] = {'success': True, 'data': ioc.whois_data}

    _, breakdown = calculate_threat_score(ioc.ioc_type, api_results)

    pdf_buffer = generate_ioc_report(ioc, breakdown)

    response = HttpResponse(pdf_buffer.read(), content_type='application/pdf')
    filename = f'threatlens_{ioc.value}_{ioc.threat_score}.pdf'
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response

def bulk_search(request):
    """CSV ile toplu IOC sorgulama"""
    form = CSVUploadForm()
    results = []
    errors = []

    if request.method == 'POST':
        form = CSVUploadForm(request.POST, request.FILES)
        if form.is_valid():
            csv_file = request.FILES['csv_file']

            # Dosya boyutu kontrolü (max 1MB)
            if csv_file.size > 1024 * 1024:
                messages.error(request, 'Dosya boyutu 1MB\'dan büyük olamaz.')
                return render(request, 'core/bulk_search.html', {'form': form})

            try:
                file_wrapper = TextIOWrapper(csv_file.file, encoding='utf-8')
                reader = csv.reader(file_wrapper)
                ioc_list = []

                for row_num, row in enumerate(reader, 1):
                    if row_num > 50:
                        messages.warning(request, 'Maksimum 50 IOC işlendi, geri kalanı atlandı.')
                        break
                    if not row or not row[0].strip():
                        continue
                    ioc_list.append(row[0].strip())

                if not ioc_list:
                    messages.error(request, 'CSV dosyasında IOC bulunamadı.')
                    return render(request, 'core/bulk_search.html', {'form': form})

                # Her IOC'yi sorgula
                for value in ioc_list:
                    ioc_type = detect_ioc_type(value)
                    if not ioc_type:
                        errors.append({'value': value, 'error': 'Tanınamadı'})
                        continue

                    is_valid, error_msg = validate_ioc(value, ioc_type)
                    if not is_valid:
                        errors.append({'value': value, 'error': error_msg})
                        continue

                    # DB'de var mı kontrol et
                    ioc, created = IOC.objects.get_or_create(
                        value=value,
                        ioc_type=ioc_type,
                    )

                    if not created:
                        ioc.query_count += 1

                    # API sorgularını çalıştır
                    start_time = time.time()
                    api_results = {}
                    sources_queried = []

                    if ioc_type == 'ip':
                        abuseipdb_result = abuseipdb_check(value)
                        api_results['abuseipdb'] = abuseipdb_result
                        sources_queried.append('abuseipdb')
                        if abuseipdb_result['success']:
                            data = abuseipdb_result['data']
                            ioc.abuseipdb_data = data
                            ioc.country_code = data.get('country_code', '')
                            ioc.country = data.get('country_name', '')
                            ioc.isp = data.get('isp', '')

                        vt_result = vt_check_ip(value)
                        api_results['virustotal'] = vt_result
                        sources_queried.append('virustotal')
                        if vt_result['success']:
                            ioc.virustotal_data = vt_result['data']

                        otx_result = otx_check_ip(value)
                        api_results['alienvault'] = otx_result
                        sources_queried.append('alienvault')
                        if otx_result['success']:
                            ioc.alienvault_data = otx_result['data']

                        # Shodan
                        shodan_result = shodan_check(value)
                        api_results['shodan'] = shodan_result
                        sources_queried.append('shodan')
                        if shodan_result['success']:
                            ioc.shodan_data = shodan_result['data']

                        ipinfo_result = ipinfo_check(value)
                        api_results['ipinfo'] = ipinfo_result
                        sources_queried.append('ipinfo')
                        if ipinfo_result['success']:
                            ioc.ipinfo_data = ipinfo_result['data']
                            if not ioc.country_code and ipinfo_result['data'].get('country'):
                                ioc.country_code = ipinfo_result['data']['country']
                                ioc.country = ipinfo_result['data'].get('country_name', '')

                    elif ioc_type == 'domain':
                        vt_result = vt_check_domain(value)
                        api_results['virustotal'] = vt_result
                        sources_queried.append('virustotal')
                        if vt_result['success']:
                            ioc.virustotal_data = vt_result['data']

                        otx_result = otx_check_domain(value)
                        api_results['alienvault'] = otx_result
                        sources_queried.append('alienvault')
                        if otx_result['success']:
                            ioc.alienvault_data = otx_result['data']

                    elif ioc_type == 'url':
                        vt_result = vt_check_url(value)
                        api_results['virustotal'] = vt_result
                        sources_queried.append('virustotal')
                        if vt_result['success']:
                            ioc.virustotal_data = vt_result['data']

                    elif ioc_type == 'hash':
                        vt_result = vt_check_hash(value)
                        api_results['virustotal'] = vt_result
                        sources_queried.append('virustotal')
                        if vt_result['success']:
                            ioc.virustotal_data = vt_result['data']

                        otx_result = otx_check_hash(value)
                        api_results['alienvault'] = otx_result
                        sources_queried.append('alienvault')
                        if otx_result['success']:
                            ioc.alienvault_data = otx_result['data']
                        
                        # WHOIS
                        whois_result = whois_check(value)
                        api_results['whois'] = whois_result
                        sources_queried.append('whois')
                        if whois_result['success']:
                            ioc.whois_data = whois_result['data']

                    # Skor hesapla ve kaydet
                    score, _ = calculate_threat_score(ioc_type, api_results)
                    ioc.threat_score = score
                    ioc.severity = get_severity(score)
                    ioc.save()

                    elapsed_ms = int((time.time() - start_time) * 1000)
                    QueryLog.objects.create(
                        ioc=ioc,
                        sources_queried=sources_queried,
                        response_time_ms=elapsed_ms,
                    )

                    results.append(ioc)

                messages.success(request, f'{len(results)} IOC başarıyla sorgulandı.')

            except Exception as e:
                messages.error(request, f'CSV işleme hatası: {str(e)}')

    return render(request, 'core/bulk_search.html', {
        'form': form,
        'results': results,
        'errors': errors,
    })

def compare(request):
    """İki IOC'yi yan yana karşılaştır"""
    ioc1 = None
    ioc2 = None
    breakdown1 = []
    breakdown2 = []

    ioc1_id = request.GET.get('ioc1')
    ioc2_id = request.GET.get('ioc2')

    if ioc1_id:
        try:
            ioc1 = IOC.objects.get(id=ioc1_id)
            api_results = {}
            if ioc1.abuseipdb_data:
                api_results['abuseipdb'] = {'success': True, 'data': ioc1.abuseipdb_data}
            if ioc1.virustotal_data:
                api_results['virustotal'] = {'success': True, 'data': ioc1.virustotal_data}
            if ioc1.ipinfo_data:
                api_results['ipinfo'] = {'success': True, 'data': ioc1.ipinfo_data}
            if ioc1.alienvault_data:
                api_results['alienvault'] = {'success': True, 'data': ioc1.alienvault_data}
            if ioc1.shodan_data:
                api_results['shodan'] = {'success': True, 'data': ioc1.shodan_data}
            if ioc1.whois_data:
                api_results['whois'] = {'success': True, 'data': ioc1.whois_data}
            _, breakdown1 = calculate_threat_score(ioc1.ioc_type, api_results)
        except IOC.DoesNotExist:
            pass

    if ioc2_id:
        try:
            ioc2 = IOC.objects.get(id=ioc2_id)
            api_results = {}
            if ioc2.abuseipdb_data:
                api_results['abuseipdb'] = {'success': True, 'data': ioc2.abuseipdb_data}
            if ioc2.virustotal_data:
                api_results['virustotal'] = {'success': True, 'data': ioc2.virustotal_data}
            if ioc2.ipinfo_data:
                api_results['ipinfo'] = {'success': True, 'data': ioc2.ipinfo_data}
            if ioc2.alienvault_data:
                api_results['alienvault'] = {'success': True, 'data': ioc2.alienvault_data}
            if ioc2.shodan_data:
                api_results['shodan'] = {'success': True, 'data': ioc2.shodan_data}
            if ioc2.whois_data:
                api_results['whois'] = {'success': True, 'data': ioc2.whois_data}
            _, breakdown2 = calculate_threat_score(ioc2.ioc_type, api_results)
        except IOC.DoesNotExist:
            pass

    # Mevcut tüm IOC'leri seçim için listele
    all_iocs = IOC.objects.all()[:50]

    return render(request, 'core/compare.html', {
        'ioc1': ioc1,
        'ioc2': ioc2,
        'breakdown1': breakdown1,
        'breakdown2': breakdown2,
        'all_iocs': all_iocs,
    })

def register(request):
    """Kullanıcı kayıt"""
    if request.user.is_authenticated:
        return redirect('index')

    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, f'Hoş geldiniz {user.username}! Hesabınız oluşturuldu.')
            return redirect('index')
    else:
        form = RegisterForm()

    return render(request, 'auth/register.html', {'form': form})

@login_required
def profile(request):
    """Kullanıcı profil sayfası"""
    user = request.user
    user_iocs = IOC.objects.filter(user=user).order_by('-last_queried')
    user_queries = QueryLog.objects.filter(ioc__user=user)

    # İstatistikler
    total_iocs = user_iocs.count()
    total_queries = user_queries.count()
    malicious_count = user_iocs.filter(severity='malicious').count()
    suspicious_count = user_iocs.filter(severity='suspicious').count()
    safe_count = user_iocs.filter(severity='safe').count()

    # En çok sorgulanan IOC'ler
    top_queried = user_iocs.order_by('-query_count')[:5]

    # En tehlikeli IOC'ler
    top_threats = user_iocs.filter(threat_score__gt=30).order_by('-threat_score')[:5]

    # API Key
    from .models import APIKey
    try:
        api_key = APIKey.objects.get(user=user)
    except APIKey.DoesNotExist:
        api_key = None

    return render(request, 'core/profile.html', {
        'total_iocs': total_iocs,
        'total_queries': total_queries,
        'malicious_count': malicious_count,
        'suspicious_count': suspicious_count,
        'safe_count': safe_count,
        'top_queried': top_queried,
        'top_threats': top_threats,
        'recent_iocs': user_iocs[:10],
        'api_key': api_key,
    })

@login_required
def generate_api_key(request):
    """API key oluştur veya yenile"""
    import secrets
    from .models import APIKey

    api_key, created = APIKey.objects.get_or_create(
        user=request.user,
        defaults={'key': secrets.token_hex()}
    )

    if not created:
        # Mevcut key'i yenile
        api_key.key = secrets.token_hex()
        api_key.requests_today = 0
        api_key.save()
        messages.success(request, 'API key yenilendi.')
    else:
        messages.success(request, 'API key oluşturuldu.')

    return redirect('profile')

def api_docs_page(request):
    """API dokümantasyon web sayfası"""
    return render(request, 'core/api_docs.html')

def custom_404(request, exception):
    return render(request, '404.html', status=404)

def custom_500(request):
    return render(request, '500.html', status=500)

@login_required
def delete_ioc(request, ioc_id):
    """IOC sil"""
    ioc = get_object_or_404(IOC, id=ioc_id)

    # Sadece sahibi veya admin silebilir
    if ioc.user != request.user and not request.user.is_staff:
        messages.error(request, 'Bu IOC\'yi silme yetkiniz yok.')
        return redirect('result', ioc_id=ioc.id)

    if request.method == 'POST':
        value = ioc.value
        ioc.delete()
        messages.success(request, f'"{value}" silindi.')
        return redirect('history')

    return render(request, 'core/confirm_delete.html', {'ioc': ioc})

def export_csv(request):
    """Sorgu geçmişini CSV olarak indir"""
    import csv
    from django.http import HttpResponse

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="threatlens_export.csv"'
    response.write('\ufeff')  # UTF-8 BOM for Excel

    writer = csv.writer(response)
    writer.writerow([
        'IOC Değeri', 'Tip', 'Tehdit Skoru', 'Seviye',
        'Ülke', 'ISP', 'Sorgu Sayısı', 'İlk Sorgu', 'Son Sorgu'
    ])

    # Kullanıcıya göre filtrele
    if request.user.is_authenticated:
        iocs = IOC.objects.filter(user=request.user).order_by('-last_queried')
    else:
        iocs = IOC.objects.all().order_by('-last_queried')

    severity_labels = {'safe': 'Güvenli', 'suspicious': 'Şüpheli', 'malicious': 'Tehlikeli'}

    for ioc in iocs:
        writer.writerow([
            ioc.value,
            ioc.get_ioc_type_display(),
            f'{ioc.threat_score}/100',
            severity_labels.get(ioc.severity, ioc.severity),
            ioc.country or '-',
            ioc.isp or '-',
            ioc.query_count,
            ioc.first_seen.strftime('%d/%m/%Y %H:%M') if ioc.first_seen else '-',
            ioc.last_queried.strftime('%d/%m/%Y %H:%M') if ioc.last_queried else '-',
        ])

    return response